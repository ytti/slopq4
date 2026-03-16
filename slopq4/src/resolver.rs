use std::collections::HashSet;
use std::sync::Arc;

use futures::future::join_all;
use tokio::sync::{mpsc, Semaphore};

use crate::irr::{IrrClient, IrrConfig, IrrError};
use crate::model::{Afi, AnnotatedRoute, Asn, Report, RouteObject, RpkiStatus, WorkKey};
use crate::rpki::RpkiDb;

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("IRR error: {0}")]
    Irr(#[from] IrrError),
}

pub struct Resolver {
    pub irr_cfg: Arc<IrrConfig>,
    pub rpki: Arc<RpkiDb>,
    pub workers: usize,
}

impl Resolver {
    pub fn new(irr_cfg: IrrConfig, rpki: RpkiDb, workers: usize) -> Self {
        Self {
            irr_cfg: Arc::new(irr_cfg),
            rpki: Arc::new(rpki),
            workers,
        }
    }

    /// Resolve an AS-SET name into a fully annotated `Report`.
    pub async fn resolve(&self, as_set: &str) -> Result<Report, ResolveError> {
        // --- Step 1: expand AS-SET into flat ASN list ---
        let mut main_client = IrrClient::connect(&self.irr_cfg).await?;
        let asns = main_client.expand_as_set(as_set).await?;
        drop(main_client);

        // --- Step 2: build deduped work queue ---
        let mut seen: HashSet<WorkKey> = HashSet::new();
        let work_keys: Vec<WorkKey> = asns
            .iter()
            .flat_map(|&asn| {
                [WorkKey { afi: Afi::V4, asn }, WorkKey { afi: Afi::V6, asn }]
            })
            .filter(|k| seen.insert(*k))
            .collect();

        let total = work_keys.len();
        eprint!("[{} ASNs, {} steps] ", asns.len(), total);

        // --- Step 3: spawn workers with semaphore-bounded concurrency ---
        let sem = Arc::new(Semaphore::new(self.workers));
        let (tx, mut rx) = mpsc::unbounded_channel::<()>();

        let handles: Vec<_> = work_keys
            .into_iter()
            .map(|key| {
                let sem = Arc::clone(&sem);
                let irr_cfg = Arc::clone(&self.irr_cfg);
                let rpki = Arc::clone(&self.rpki);
                let tx = tx.clone();
                tokio::spawn(async move {
                    let _permit = sem.acquire().await.expect("semaphore closed");
                    let result = fetch_and_annotate(key, &irr_cfg, &rpki).await;
                    let _ = tx.send(());
                    (key, result)
                })
            })
            .collect();

        // Progress odometer: drain the mpsc channel as tasks complete
        drop(tx); // so the channel closes when all senders are done
        let progress_task = tokio::spawn(async move {
            while rx.recv().await.is_some() {
                eprint!(".");
            }
            eprintln!(); // newline after odometer
        });

        let task_results = join_all(handles).await;
        progress_task.await.ok();

        // --- Step 4: aggregate into Report ---
        Ok(aggregate(as_set, &asns, task_results, &self.rpki))
    }
}

/// Fetch all route objects for one (AFI, ASN) and annotate with RPKI status.
async fn fetch_and_annotate(
    key: WorkKey,
    irr_cfg: &IrrConfig,
    rpki: &RpkiDb,
) -> Result<Vec<AnnotatedRoute>, IrrError> {
    let mut client = IrrClient::connect(irr_cfg).await?;
    let prefixes = match key.afi {
        Afi::V4 => client.routes_v4(key.asn).await?,
        Afi::V6 => client.routes_v6(key.asn).await?,
    };
    let routes = prefixes
        .into_iter()
        .map(|prefix| {
            let route = RouteObject { prefix, origin: key.asn };
            let rpki_status = rpki.validate(route.prefix, route.origin);
            AnnotatedRoute { route, rpki: rpki_status }
        })
        .collect();
    Ok(routes)
}

/// Aggregate task results into the final Report.
fn aggregate(
    as_set: &str,
    all_asns: &[Asn],
    task_results: Vec<Result<(WorkKey, Result<Vec<AnnotatedRoute>, IrrError>), tokio::task::JoinError>>,
    rpki: &RpkiDb,
) -> Report {
    let mut asn_has_routes: HashSet<Asn> = HashSet::new();
    let mut prefix_valid: Vec<(String, Asn)> = vec![];
    let mut prefix_unknown: Vec<(String, Asn)> = vec![];
    let mut prefix_invalid: Vec<(String, Asn)> = vec![];

    for join_result in task_results {
        let (key, fetch_result) = match join_result {
            Ok(pair) => pair,
            Err(_) => continue, // task panicked — skip
        };
        let routes = match fetch_result {
            Ok(r) => r,
            Err(_) => continue, // IRR error — treat as no routes
        };

        for ar in routes {
            asn_has_routes.insert(key.asn);
            match ar.rpki {
                RpkiStatus::Valid => {
                    prefix_valid.push((ar.route.prefix.to_string(), ar.route.origin));
                }
                RpkiStatus::Unknown => {
                    prefix_unknown.push((ar.route.prefix.to_string(), ar.route.origin));
                }
                RpkiStatus::Invalid => {
                    prefix_invalid.push((ar.route.prefix.to_string(), ar.route.origin));
                }
            }
        }
    }

    let mut valid_asns: Vec<Asn> = vec![];
    let mut invalid_asns: Vec<Asn> = vec![];

    for &asn in all_asns {
        if asn_has_routes.contains(&asn) || rpki.asn_has_roa(asn) {
            valid_asns.push(asn);
        } else {
            invalid_asns.push(asn);
        }
    }

    valid_asns.sort_unstable();
    invalid_asns.sort_unstable();
    prefix_valid.sort_unstable_by_key(|(p, a)| (p.clone(), *a));
    prefix_unknown.sort_unstable_by_key(|(p, a)| (p.clone(), *a));
    prefix_invalid.sort_unstable_by_key(|(p, a)| (p.clone(), *a));

    Report {
        as_set: as_set.to_owned(),
        asns: crate::model::AsnReport { valid: valid_asns, invalid: invalid_asns },
        prefix: crate::model::PrefixReport {
            valid: prefix_valid,
            unknown: prefix_unknown,
            invalid: prefix_invalid,
        },
    }
}
