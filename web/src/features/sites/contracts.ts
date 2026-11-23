// Public ingress/deployment JSON contracts. Internal snapshots and credentials never enter this model.
export interface MaterialRef {
    id: string;
    revision: number;
    status: string;
}
export interface RatePolicy {
    requests_per_second: number;
    burst: number;
    connections: number;
    status: number;
}
export interface Route {
    match: string;
    path: string;
    strip_prefix: boolean;
    target: {
        id?: string;
    };
    rate?: RatePolicy;
}
export interface SiteConfig {
    enabled: boolean;
    domains: string[];
    default_target: {
        id?: string;
    };
    routes: Route[];
    maintenance: {
        enabled: boolean;
        status: number;
        message: string;
    };
    cloudflare: {
        mode: string;
        trusted_proxy_networks: string[];
        require_origin_pull: boolean;
    };
    entry_certificate?: MaterialRef;
    client_verification: {
        mode: string;
        trust?: MaterialRef;
        depth: number;
        revocation: string;
    };
    access: {
        allow: string[];
        deny: string[];
        deny_paths: string[];
    };
    rate: RatePolicy;
    connection: {
        connect_timeout_seconds: number;
        read_timeout_seconds: number;
        send_timeout_seconds: number;
        max_body_bytes: number;
        websocket: boolean;
        sse: boolean;
        buffer_responses: boolean;
    };
}
export interface Site {
    id: string;
    name: string;
    group_ids: string[];
    revision: number;
    draft: SiteConfig;
    published_revision: number;
    published?: SiteConfig;
}
export interface Group {
    id: string;
    name: string;
    revision: number;
}
export interface TargetConfig {
    name: string;
    protocol: string;
    members: {
        address: string;
        port: number;
        weight: number;
        tls_name: string;
    }[];
    http_host: string;
    tls_name_mode: string;
    tls_server_name_mode?: string;
    tls_name: string;
    trust?: MaterialRef;
    client_certificate?: MaterialRef;
    allowed_networks: string[];
    health: {
        enabled: boolean;
        http_host: string;
        path: string;
        interval_seconds: number;
        timeout_seconds: number;
        healthy_threshold: number;
        unhealthy_threshold: number;
    };
}
export interface Target {
    id: string;
    revision: number;
    config: TargetConfig;
    published_revision: number;
    published?: TargetConfig;
}
export interface Revision {
    resource_id: string;
    number: number;
}
export interface Candidate {
 node_progress?: {expected:number;succeeded:number;failed:number;state:string;complete:boolean;degraded:boolean;nodes:{event_id?:string;node:{id:string;epoch:number};release_id:string;artifact_id:string;generation:string;image_digest?:string;observed_at:string;state:string;node_state:string}[]};
 execution?: {stage:string;cause:string;updated_at:string;job_state:string;attempt:number;config_applied:boolean;route_verification?:{artifact_id:string;version:string;generation:string;checked_at:string;native_verified:boolean;business_verified:boolean;routes:{site_id:string;route:string;outcome:string;reason?:string}[]}};
    id: string;
    input_digest: string;
    affected_site_ids: string[];
    changes: {
        kind: string;
        id: string;
        before: number;
        after: number;
        fields: string[];
    }[];
    state: string;
    effective: boolean;
    observed_version: string;
    restored_version: string;
}
export interface Preflight {
    site_id: string;
    revision: number;
    entry: {
        role: string;
        mode: string;
        address: string;
        domain: string;
        path: string;
    };
    ready: boolean;
    result: string;
    reason?: string;
}
export const emptyRate = (): RatePolicy => ({ requests_per_second: 0, burst: 0, connections: 0, status: 429 });
export const newSite = (): SiteConfig => ({ enabled: true, domains: [], default_target: {}, routes: [], maintenance: { enabled: false, status: 503, message: '' }, cloudflare: { mode: 'off', trusted_proxy_networks: [], require_origin_pull: false }, client_verification: { mode: 'off', depth: 0, revocation: '' }, access: { allow: [], deny: [], deny_paths: [] }, rate: emptyRate(), connection: { connect_timeout_seconds: 5, read_timeout_seconds: 60, send_timeout_seconds: 60, max_body_bytes: 10485760, websocket: false, sse: false, buffer_responses: true } });
export const newTarget = (): TargetConfig => ({ name: '', protocol: 'http', members: [{ address: '', port: 80, weight: 1, tls_name: '' }], http_host: '', tls_server_name_mode: '', tls_name_mode: '', tls_name: '', allowed_networks: [], health: { enabled: false, http_host: '', path: '/', interval_seconds: 5, timeout_seconds: 2, healthy_threshold: 2, unhealthy_threshold: 3 } });
export const lines = (v: string) => v.split(/[\n,]/);
