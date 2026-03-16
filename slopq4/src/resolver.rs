use std::collections::HashSet;
use std::sync::Arc;

use futures::future::join_all;
use tokio::sync::{mpsc, Semaphore};

use crate::irr::{fetch_routes_with_rpki, IrrClient, IrrConfig, IrrError};
use crate::model::{Afi, AnnotatedRoute, Asn, Report, RouteObject, RpkiStatus, WorkKey};
use crate::rpki::RpkiDb;

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("IRR error: {0}")]
    Irr(#[from] IrrError),
}

pub struct Resolver {
    pub irr_cfg: Arc<IrrConfig>,
    /// `None` = use IRRd4 inline `rpki-ov-state`; `Some` = local RPKI validation.
    pub rpki: Option<Arc<RpkiDb>>,
    pub workers: usize,
}

impl Resolver {
    pub fn new(irr_cfg: IrrConfig, rpki: Option<RpkiDb>, workers: usize) -> Self {
        Self {
            irr_cfg: Arc::new(irr_cfg),
            rpki: rpki.map(Arc::new),
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
                let rpki = self.rpki.as_ref().map(Arc::clone);
                let tx = tx.clone();
                tokio::spawn(async move {
                    let _permit = sem.acquire().await.expect("semaphore closed");
                    let result = fetch_and_annotate(key, &irr_cfg, rpki.as_deref()).await;
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

        // Surface MissingRpkiState immediately rather than silently treating it as no routes.
        for result in &task_results {
            if let Ok((_, Err(IrrError::MissingRpkiState))) = result {
                return Err(ResolveError::Irr(IrrError::MissingRpkiState));
            }
        }

        // --- Step 4: aggregate into Report ---
        Ok(aggregate(as_set, &asns, task_results, self.rpki.as_deref()))
    }
}

/// Fetch all route objects for one (AFI, ASN) and annotate with RPKI status.
///
/// - `rpki = Some(db)`: use `!g`/`!6` prefix queries + local `RpkiDb` validation.
/// - `rpki = None`: use RPSL object query, map `rpki-ov-state` to `RpkiStatus`.
async fn fetch_and_annotate(
    key: WorkKey,
    irr_cfg: &IrrConfig,
    rpki: Option<&RpkiDb>,
) -> Result<Vec<AnnotatedRoute>, IrrError> {
    if let Some(db) = rpki {
        let mut client = IrrClient::connect(irr_cfg).await?;
        // Local RPKI path: fast prefix-list query + local validation.
        let prefixes = match key.afi {
            Afi::V4 => client.routes_v4(key.asn).await?,
            Afi::V6 => client.routes_v6(key.asn).await?,
        };
        Ok(prefixes
            .into_iter()
            .map(|prefix| {
                let route = RouteObject { prefix, origin: key.asn };
                let rpki_status = db.validate(route.prefix, route.origin);
                AnnotatedRoute { route, rpki: rpki_status }
            })
            .collect())
    } else {
        // IRRd4 inline RPKI path: non-persistent RPSL text query with rpki-ov-state.
        let irr_routes = fetch_routes_with_rpki(irr_cfg, key.asn, key.afi).await?;
        Ok(irr_routes
            .into_iter()
            .map(|r| {
                let rpki_status = match r.rpki_ov_state.as_deref() {
                    Some("valid")     => RpkiStatus::Valid,
                    Some("not_found") => RpkiStatus::Unknown,
                    None => {
                        tracing::warn!(prefix = %r.prefix, asn = key.asn, "no rpki-ov-state");
                        RpkiStatus::Unknown
                    }
                    Some(other) => {
                        tracing::warn!(prefix = %r.prefix, asn = key.asn, state = other, "unexpected rpki-ov-state");
                        RpkiStatus::Invalid
                    }
                };
                AnnotatedRoute {
                    route: RouteObject { prefix: r.prefix, origin: key.asn },
                    rpki: rpki_status,
                }
            })
            .collect())
    }
}

/// Aggregate task results into the final Report.
fn aggregate(
    as_set: &str,
    all_asns: &[Asn],
    task_results: Vec<Result<(WorkKey, Result<Vec<AnnotatedRoute>, IrrError>), tokio::task::JoinError>>,
    rpki: Option<&RpkiDb>,
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
        let is_valid = asn_has_routes.contains(&asn)
            || rpki.map_or(false, |db| db.asn_has_roa(asn));
        if is_valid {
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
