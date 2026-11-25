#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
manifest= nodes= budget= suite=all
while [ "$#" -gt 0 ]; do
 case "$1" in
 --manifest) manifest=$2;shift 2;;
 --nodes) nodes=$2;shift 2;;
 --budget) budget=$2;shift 2;;
 --suite) suite=$2;shift 2;;
 *) echo 'usage: check-multinode.sh --manifest FILE --nodes FILE --budget FILE [--suite all|runtime|control|upgrade|capacity|bootstrap|maintenance|inventory]' >&2;exit 2;;
 esac
done
[ -n "$manifest" ] && [ -n "$nodes" ] && [ -n "$budget" ] || { echo 'explicit manifest, owned node config and budget required' >&2;exit 2; }
python3 scripts/check-multinode-inputs.py "$manifest" "$nodes" "$budget"
GATEBEAM_MULTINODE_NODES=$(python3 -c 'import os,sys;print(os.path.abspath(sys.argv[1]))' "$nodes")
GATEBEAM_MULTINODE_BUDGET=$(python3 -c 'import os,sys;print(os.path.abspath(sys.argv[1]))' "$budget")
export GATEBEAM_MULTINODE_NODES GATEBEAM_MULTINODE_BUDGET
GATEBEAM_MULTINODE_MANIFEST=$(python3 -c 'import os,sys;print(os.path.abspath(sys.argv[1]))' "$manifest")
export GATEBEAM_MULTINODE_MANIFEST
export GATEBEAM_MULTINODE_REPORT="$PWD/.work/system-acceptance/multinode"
mkdir -p .work/build "$GATEBEAM_MULTINODE_REPORT"
arch=$(docker image inspect gatebeam-edge:local --format '{{.Architecture}}')
python3 scripts/aggregate-command.py 90 env GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go test -c -p 2 -tags integration -o .work/build/multinode-capabilities ./tests/integration/multinode
export GATEBEAM_COMPOSE_GATEWAY_BINARY="$PWD/.work/build/gatebeam"
export GATEBEAM_COMPOSE_ADMIN_BINARY="$PWD/.work/build/gatebeam-admin"
export GATEBEAM_COMPOSE_PROBE_BINARY="$PWD/.work/build/multinode-capabilities"
export GATEBEAM_COMPOSE_EXACT_IMAGES=1
runtime=TestBothNodesColdStartWithAllControlDependenciesStopped
inventory='TestSingleNodeColdStartWithAllControlDependenciesStopped TestThreeNodesPublishAndRollWithoutLosingNewRequests TestTemporarySecondNodeCarriesTrafficDuringOriginalUpgrade TestCapacityLossReattachesGatewayBeforeDrain'
control='TestDualControlFailuresAndQueryCoverage TestPrivateTLSRotationAndRevocationAcrossRestart TestFunctionalCanaryRejectsQueryAndArchiveFailures TestPrivateRolesObtainAndAutomaticallyLoadStandardACME TestCapsuleEnabledMaintenanceSurvivesEdgeControlRestart TestWorkerConstructorFailureBlocksReadinessButPreservesLocalQueries'
upgrade='TestExecutorProcessInterruptionAndRejectedVersion TestWholeNodeMaintenanceRetainsOfflineBoot'
capacity=TestSingleNodeMeasuredCapacityWithQueryContention
case "$suite" in
 runtime) cases=$runtime;;
 control) cases=$control;;
 upgrade) cases=$upgrade;;
 capacity) cases=$capacity;;
 bootstrap) cases="$runtime $control $inventory";;
 maintenance) cases=$upgrade;;
 inventory) cases=$inventory;;
 all) cases="$runtime $control $upgrade $capacity $inventory";;
 *) echo 'unknown suite' >&2;exit 2;;
esac
for test in $cases; do
 # A missing scenario must never turn into a successful "no tests to run".
 go test -tags integration -list "^$test$" ./tests/integration/multinode | rg -Fx "$test" >/dev/null
 sh scripts/check-db.sh ./tests/integration/multinode -run "^$test$" -v
done
