import { request } from '../../api/client';
import { useAuth } from '../auth/store';
import { computed } from 'vue';
export async function all<T>(path: string): Promise<T[]> {
    const result: T[] = [];
    for (let offset = 0; offset <= 100000;) {
        const page = await request<{ items: T[] | null; has_more?: boolean; next_offset?: number | null }>(`${path}?limit=100&offset=${offset}`);
        const items = page.items || [];
        result.push(...items);
        if (typeof page.has_more === 'boolean') {
            if (!page.has_more) return result;
            const next = page.next_offset;
            if (typeof next !== 'number' || !Number.isInteger(next) || next <= offset || next > offset + 100)
                throw new Error('分页响应无效。');
            offset = next;
        } else {
            // Existing non-filtered resource contracts retain length pagination.
            if (items.length < 100) return result;
            offset += 100;
        }
    }
    throw new Error('资源超过查询范围，请缩小授权范围。');
}
export function permissions() { const auth = useAuth(); return { canEdit: computed(() => ['admin', 'editor', 'publisher'].includes(auth.actor?.role || '')), canPublish: computed(() => ['admin', 'publisher'].includes(auth.actor?.role || '')), isAdmin: computed(() => auth.actor?.role === 'admin') }; }
export const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value));
export const message = (e: unknown) => e instanceof Error ? e.message : '请求失败。';
export interface CreationCapabilities {
    create_site_group_ids: string[];
    create_ungrouped_site: boolean;
    create_target: boolean;
    manage_groups: boolean;
}
export const emptyCapabilities = (): CreationCapabilities => ({ create_site_group_ids: [], create_ungrouped_site: false, create_target: false, manage_groups: false });
export async function capabilities(groups: {
    id: string;
}[] = []): Promise<CreationCapabilities> { const result = await request<CreationCapabilities>('/ingress-capabilities'); for (let i = 0; i < groups.length; i += 100) {
    const page = await request<CreationCapabilities>('/ingress-capabilities?group_ids=' + groups.slice(i, i + 100).map(g => g.id).join(','));
    result.create_site_group_ids.push(...page.create_site_group_ids);
} return result; }
