<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { request } from '../../api/client';
import { all, message, permissions } from '../sites/data';
import type { Site, Target, Candidate } from '../sites/contracts';
const { canPublish } = permissions();
const sites = ref<Site[]>([]), targets = ref<Target[]>([]), releases = ref<Candidate[]>([]);
const selected = ref<string[]>([]), selectedTargets = ref<string[]>([]), sourceID = ref('');
const candidate = ref<Candidate>(), acknowledgment = ref<{ id: string; digest: string }>();
const actionBusy = ref(false), pendingLists = ref(0), error = ref(''), notice = ref('');
const busy = computed(() => actionBusy.value || pendingLists.value > 0);
let requestOwner = 0, listOwner = 0, disposed = false, polling = false;
let timer: ReturnType<typeof setInterval> | undefined;
const activeStates = ['queued', 'preparing', 'validated', 'applying', 'verifying', 'restoring'];
const stateText: Record<string, string> = { prepared: '候选已准备，尚未排队', queued: '已排队，尚未确认生效', preparing: '正在准备', validated: '原生配置校验通过', applying: '正在切换入口', verifying: '正在实测', succeeded: '已验证成功', failed: '发布失败，恢复未获确认', restoring: '正在恢复，尚未确认', restored: '发布失败，已验证恢复', restore_failed: '发布失败，恢复失败' };
const nodeIdentityText: Record<string,string> = {active:'有效',quarantined:'已隔离',revoked:'已撤销',stale:'旧代次',disabled:'已移出入口'};
const nodeResultText: Record<string,string> = {waiting:'等待实际结果',succeeded:'已验证成功',failed:'执行失败',restored:'执行失败，已恢复',restore_failed:'执行失败，恢复失败',restricted:'已按本地安全状态收紧，等待对账'};
function releaseState(value: Candidate) {
    const progress=value.node_progress;
    if (!progress) return stateText[value.state]||'未知状态：'+value.state;
    if (progress.degraded) return '节点状态已降级，不能确认全部入口生效';
    if (progress.complete) return '全部目标节点已验证成功';
    if (progress.state==='partial_success') return '部分成功，仍有入口未确认生效';
    if (progress.state==='failed') return '所有目标节点执行失败';
    return '等待目标节点逐一确认';
}
function pending(value: Candidate) {
    if (!value.node_progress) return activeStates.includes(value.state);
    return value.node_progress.nodes.some(node=>['waiting','preparing','validated','applying','verifying','restoring','restricted'].includes(node.state));
}
const current = (owner: number) => !disposed && owner === requestOwner;
const reviewed = computed({
    get: () => !!candidate.value && acknowledgment.value?.id === candidate.value.id && acknowledgment.value.digest === candidate.value.input_digest,
    set: (checked: boolean) => {
        acknowledgment.value = checked && candidate.value?.state === 'prepared' && !busy.value
            ? { id: candidate.value.id, digest: candidate.value.input_digest } : undefined;
    },
});
function begin(clear: boolean) {
    const owner = ++requestOwner;
    acknowledgment.value = undefined;
    if (clear) candidate.value = undefined;
    actionBusy.value = true;
    error.value = '';
    notice.value = '';
    return owner;
}
async function run(owner: number, fn: () => Promise<void>) {
    try { await fn(); }
    catch (e) { if (current(owner)) error.value = message(e); }
    finally { if (current(owner)) actionBusy.value = false; }
}
async function load(owner = requestOwner) {
    const list = ++listOwner;
    const values = await Promise.all([all<Site>('/sites'), all<Target>('/targets'), all<Candidate>('/releases')]);
    if (current(owner) && list === listOwner) [sites.value, targets.value, releases.value] = values;
}
async function refreshLists() {
    const owner = requestOwner;
    pendingLists.value++;
    try { await load(owner); }
    catch (e) { if (current(owner)) error.value = message(e); }
    finally { pendingLists.value--; }
}
async function prepare() {
    const owner = begin(true);
    const siteIDs = [...selected.value], targetIDs = [...selectedTargets.value], historicalID = sourceID.value;
    await run(owner, async () => {
        const expected: Record<string, number> = {};
        for (const id of siteIDs) {
            const site = sites.value.find(s => s.id === id);
            if (!site) throw new Error('站点列表已改变，请刷新。');
            expected['site:' + id] = site.revision;
        }
        for (const id of targetIDs) {
            const target = targets.value.find(t => t.id === id);
            if (!target) throw new Error('目标列表已改变，请刷新。');
            expected['target:' + id] = target.revision;
        }
        const value = await request<Candidate>(historicalID ? '/releases/' + historicalID + '/prepare-historical' : '/releases/prepare', { site_ids: siteIDs, expected });
        if (!current(owner)) return;
        candidate.value = value;
        await load(owner);
    });
}
async function view(id: string) {
    const owner = begin(true);
    await run(owner, async () => {
        // Keep both responses local. A newer view owns the entire displayed identity and diff.
        const [value, diff] = await Promise.all([
            request<Candidate>('/releases/' + id),
            request<Pick<Candidate, 'id' | 'changes' | 'affected_site_ids' | 'input_digest'>>('/releases/' + id + '/diff'),
        ]);
        if (!current(owner)) return;
        if (value.id !== id || diff.id !== id || value.input_digest !== diff.input_digest) throw new Error('候选与差异身份不一致，请重新读取。');
        candidate.value = { ...value, ...diff };
    });
}
async function publish() {
    const value = candidate.value, acknowledged = acknowledgment.value;
    if (!canPublish.value || busy.value || value?.state !== 'prepared' || !acknowledged || acknowledged.id !== value.id || acknowledged.digest !== value.input_digest) return;
    // Capture exactly the acknowledged identity before any await; later navigation cannot retarget this mutation.
    const id = acknowledged.id, digest = acknowledged.digest, owner = begin(false);
    await run(owner, async () => {
        await request('/releases/' + id + '/publish', {});
        const result = await request<Candidate>('/releases/' + id);
        if (!current(owner)) return;
        if (result.id !== id || result.input_digest !== digest) throw new Error('发布回执身份不一致，请重新读取。');
        candidate.value = result;
        notice.value = '已提交队列，等待真实执行结果';
        await load(owner);
    });
}
async function poll() {
    const value = candidate.value;
    if (polling || busy.value || !value || !pending(value)) return;
    const owner = requestOwner, id = value.id, digest = value.input_digest;
    polling = true;
    try {
        const result = await request<Candidate>('/releases/' + id);
        if (!current(owner) || candidate.value !== value) return;
        if (result.id !== id || result.input_digest !== digest) throw new Error('发布状态身份不一致，请重新读取。');
        candidate.value = result;
        error.value = '';
        if (!pending(result)) await load(owner);
    } catch (e) { if (current(owner)) error.value = message(e); }
    finally { polling = false; }
}
onMounted(() => { void refreshLists(); timer = setInterval(() => void poll(), 1000); });
onUnmounted(() => { disposed = true; requestOwner++; acknowledgment.value = undefined; if (timer) clearInterval(timer); });
</script>
<template>
<section>
<h1>发布审阅</h1>
<p class="muted">仅显式选中的草稿进入候选。未选站点和共享目标保留当前已发布版本。提交时及执行前后端重新核对身份、引用闭包和修订。</p>
<p v-if="error" role="alert">{{error}}</p>
<p v-if="notice" role="status">{{notice}}</p>
<section class="panel">
<h2>选择草稿</h2>
<fieldset :disabled="busy||!canPublish">
<h3>站点</h3>
<label v-for="s in sites" :key="s.id" class="check">
<input v-model="selected" type="checkbox" :value="s.id" :data-testid="'select-site-'+s.id">{{s.name}} · site:{{s.id}} · 草稿 {{s.revision}} / 已发布 {{s.published_revision||'无'}}</label>
<h3>共享目标草稿（明确选择）</h3>
<p class="muted">首次引用尚未发布的目标时，也必须选中该目标草稿。保留已发布目标时请勿勾选。</p>
<label v-for="t in targets" :key="t.id" class="check">
<input v-model="selectedTargets" type="checkbox" :value="t.id" :data-testid="'select-target-'+t.id">{{t.config.name}} · target:{{t.id}} · 草稿 {{t.revision}} / 已发布 {{t.published_revision||'无'}}</label>
<label>历史已验证来源（可选）<select v-model="sourceID">
<option value="">当前草稿</option>
<option v-for="r in releases.filter(v=>v.state==='succeeded')" :key="r.id" :value="r.id">{{r.id}}</option>
</select>
</label>
<p class="muted">历史重发生成新候选，仍核对当前授权、head 和当前材料；不会回退安全状态。</p>
</fieldset>
<button :disabled="!canPublish||busy||selected.length===0" @click="prepare">生成候选并校验</button>
<p v-if="!canPublish" class="muted">当前角色没有发布权限。</p>
</section>
<section v-if="candidate" class="panel">
<h2>候选差异</h2>
<p class="mono">候选 {{candidate.id}}<br>输入摘要 {{candidate.input_digest}}</p>
<h3>服务端核验的共享影响闭包</h3>
<ul>
<li v-for="id in candidate.affected_site_ids" :key="id" class="mono">{{sites.find(s=>s.id===id)?.name||'授权站点'}} · {{id}}</li>
</ul>
<div data-testid="candidate-changes" class="table-scroll">
<table>
<thead>
<tr>
<th>资源类型 / ID</th>
<th>已发布 → 候选修订</th>
<th>变化字段</th>
</tr>
</thead>
<tbody>
<tr v-for="change in candidate.changes" :key="change.kind+change.id">
<td class="mono">{{change.kind}}:{{change.id}}</td>
<td>{{change.before}} → {{change.after}}</td>
<td>{{change.fields.join('、')||'无字段变化'}}</td>
</tr>
</tbody>
</table>
</div>
<p data-testid="release-state" role="status">{{releaseState(candidate)}}。{{candidate.effective?'此发布是当前数据库确认的版本；实时可达性需独立探测。':'此发布不是当前数据库确认的版本；历史执行结果见发布状态，实时可达性需独立探测。'}}<span v-if="['failed','restore_failed','restored'].includes(candidate.state)&&(!candidate.execution||candidate.execution.cause==='unavailable')"> 失败原因不可用，服务端未提供可核验的具体原因。</span>
</p>
<section v-if="candidate.node_progress" data-testid="node-release-progress">
<p>节点确认：{{candidate.node_progress.succeeded}} / {{candidate.node_progress.expected}}；执行失败 {{candidate.node_progress.failed}}。<span v-if="candidate.node_progress.degraded">存在已隔离、撤销或代次不匹配的节点，不能据此确认全部入口。</span></p>
<div class="table-wrap"><table><thead><tr><th>节点</th><th>代次</th><th>发布结果</th><th>身份状态</th><th>实际产物 / 运行代次</th><th>最近确认时间</th></tr></thead>
<tbody><tr v-for="node in candidate.node_progress.nodes" :key="node.node.id+'/'+node.node.epoch"><td class="mono">{{node.node.id}}</td><td>{{node.node.epoch}}</td><td>{{nodeResultText[node.state]||'等待实际结果'}}</td><td>{{nodeIdentityText[node.node_state]||'未知'}}</td><td class="mono">{{node.artifact_id||'尚未确认'}}<br>{{node.generation||'尚未确认'}}</td><td>{{node.event_id?node.observed_at:'尚未上报'}}</td></tr></tbody></table></div>
</section>
<section v-else-if="candidate.execution" data-testid="execution-report"><p>执行阶段 {{candidate.execution.stage}} · 原因 {{candidate.execution.cause}} · 任务 {{candidate.execution.job_state}} / 尝试 {{candidate.execution.attempt}} · {{candidate.execution.updated_at}}</p><p>配置加载：{{candidate.execution.config_applied?'当前数据库已确认':'未确认当前加载'}}；业务路由：{{candidate.execution.route_verification?.business_verified?'所列受影响路由已验证':'未完成业务验收'}}</p><div v-if="candidate.execution.route_verification"><p>产物 {{candidate.execution.route_verification.artifact_id}} · 原生版本 {{candidate.execution.route_verification.version}} · generation {{candidate.execution.route_verification.generation}} · {{candidate.execution.route_verification.checked_at}}</p><p v-for="(r,i) in candidate.execution.route_verification.routes" :key="i">{{r.site_id}} / {{r.route||'默认'}}：{{r.outcome}} {{r.reason}}</p></div></section>
<dl>
<dt>数据库记录的版本观察 / runtime generation（非当前实时探测）</dt>
<dd class="mono">{{candidate.observed_version||'未提供 / 未知'}}</dd>
<dt>恢复版本元数据</dt>
<dd class="mono">{{candidate.restored_version||'未提供'}} <span v-if="candidate.state!=='restored'">（不能据此确认恢复成功）</span>
</dd>
</dl>
<p v-if="!candidate.node_progress&&candidate.state==='queued'&&(!candidate.execution||candidate.execution.stage==='unavailable')" class="muted">执行阶段尚未上报；保持排队状态直到后端返回新的事实。</p>
<label class="check">
<input v-model="reviewed" type="checkbox" :disabled="!canPublish||busy||candidate.state!=='prepared'">我已审阅共享影响及修订差异</label>
<button :disabled="!canPublish||busy||!reviewed||candidate.state!=='prepared'" @click="publish">发布此候选</button>
<button :disabled="busy" @click="view(candidate.id)">刷新发布结果</button>
</section>
<section class="panel">
<h2>发布记录</h2>
<ul>
<li v-for="r in releases" :key="r.id">
<button class="mono" @click="view(r.id)">{{r.id}}</button> {{releaseState(r)}}</li>
</ul>
<button :disabled="busy" @click="refreshLists">刷新列表</button>
</section>
</section>
</template>
