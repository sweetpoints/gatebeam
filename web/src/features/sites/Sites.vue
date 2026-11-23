<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { request } from '../../api/client';
import { all, clone, message, permissions, capabilities, emptyCapabilities } from './data';
import { lines, newSite, emptyRate, type Site, type Target, type Group, type SiteConfig, type Revision, type Preflight } from './contracts';
import RateFields from './RateFields.vue';
import MaterialFields from './MaterialFields.vue';
const caps = ref(emptyCapabilities());
const { canEdit } = permissions(), sites = ref<Site[]>([]), targets = ref<Target[]>([]), groups = ref<Group[]>([]), error = ref(''), notice = ref(''), busy = ref(false);
const editing = ref(false), id = ref(''), revision = ref(0), name = ref(''), groupIDs = ref<string[]>([]), config = ref<SiteConfig>(newSite()), groupName = ref(''), groupID = ref('');
const entry = ref({ role: 'new', mode: 'direct', address: '', domain: '', path: '/' }), report = ref<Preflight>(), form = ref<HTMLFormElement>(), domainField = ref<HTMLTextAreaElement>();
async function load() { [sites.value, targets.value, groups.value] = await Promise.all([all<Site>('/sites'), all<Target>('/targets'), all<Group>('/groups')]); caps.value = await capabilities(groups.value); }
let editGeneration = 0, pendingOperations = 0;
async function perform(fn: () => Promise<void>, owns = () => true) {
    pendingOperations++;
    busy.value = true;
    if (owns()) { error.value = ''; notice.value = ''; }
    try { await fn(); }
    catch (e) { if (owns()) { caps.value = emptyCapabilities(); error.value = message(e); } }
    finally { busy.value = --pendingOperations > 0; }
}
function edit(site?: Site) { editGeneration++; notice.value = ''; error.value = ''; report.value = undefined; id.value = site?.id || ''; revision.value = site?.revision || 0; name.value = site?.name || ''; groupIDs.value = [...(site?.group_ids || [])]; config.value = site ? clone(site.draft) : newSite(); entry.value.domain = config.value.domains[0] || ''; editing.value = true; }
function setDomains(event: Event) { config.value.domains = lines((event.target as HTMLTextAreaElement).value); domainField.value?.setCustomValidity(''); }
function validDomain(value: string) { const domain = value.trim().toLowerCase().replace(/\.$/, ''); return domain.length > 0 && domain.length <= 253 && domain.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)); }
async function save() {
    domainField.value?.setCustomValidity(config.value.domains.filter(v => v.trim()).every(validDomain) ? '' : '请输入有效 ASCII 域名，每行一个，不包含协议或端口。');
    if (!form.value?.reportValidity()) return;
    const generation = editGeneration, siteID = id.value, expected = revision.value;
    const value = clone(config.value), groups = [...groupIDs.value], siteName = name.value;
    value.domains = value.domains.map(v => v.trim()).filter(Boolean);
    value.access.allow = value.access.allow.map(v => v.trim()).filter(Boolean);
    value.access.deny = value.access.deny.map(v => v.trim()).filter(Boolean);
    value.access.deny_paths = value.access.deny_paths.map(v => v.trim()).filter(Boolean);
    value.cloudflare.trusted_proxy_networks = value.cloudflare.trusted_proxy_networks.map(v => v.trim()).filter(Boolean);
    let ownedID = siteID;
    const owns = () => generation === editGeneration && id.value === ownedID;
    await perform(async () => {
        const receipt = siteID
            ? await request<Revision>('/sites/' + siteID + '/draft', { config: value, expected_revision: expected }, 'PUT')
            : await request<Revision>('/sites', { name: siteName, group_ids: groups, config: value });
        if (siteID && receipt.resource_id !== siteID) throw new Error('保存回执身份不一致，请重新读取。');
        if (owns()) {
            ownedID = receipt.resource_id;
            id.value = ownedID;
            // The form guard belongs to this mutation, never a newer head from the list reload.
            revision.value = receipt.number;
        }
        await load();
        if (owns()) notice.value = '站点草稿已保存';
    }, owns);
}
async function saveGroups() {
    const generation = editGeneration, siteID = id.value, expected = revision.value, groups = [...groupIDs.value];
    const owns = () => generation === editGeneration && id.value === siteID;
    await perform(async () => {
        await request('/sites/' + siteID + '/groups', { group_ids: groups, expected_revision: expected }, 'PUT');
        // Successful 204 acknowledges exactly one MoveTo revision increment from expected.
        if (owns()) revision.value = expected + 1;
        await load();
        if (owns()) notice.value = '所属分组已保存';
    }, owns);
}
async function saveGroup() { await perform(async () => { const existing = groups.value.find(g => g.id === groupID.value); await request('/groups' + (existing ? '/' + existing.id : ''), { name: groupName.value, expected_revision: existing?.revision || 0 }, existing ? 'PUT' : 'POST'); await load(); notice.value = '分组已保存'; }); }
async function removeGroup(g: Group) { if (!window.confirm('删除此分组？组内站点将保留。'))
    return; await perform(async () => { await request('/groups/' + g.id, { expected_revision: g.revision }, 'DELETE'); await load(); notice.value = '分组已删除，站点保留'; }); }
async function preflight() { await perform(async () => { report.value = await request<Preflight>('/sites/' + id.value + '/preflight', entry.value); }); }
onMounted(() => void perform(load));
</script>
<template>
<section>
<div class="section-heading">
<div>
<h1>站点配置</h1>
<p class="muted">保存仅更新草稿。通过发布审阅后才会改变入口。</p>
</div>
<button :disabled="busy||(!caps.create_ungrouped_site&&caps.create_site_group_ids.length===0)" @click="edit()">新建站点</button>
</div>
<p v-if="error" role="alert" class="error" tabindex="-1">{{error}}</p>
<p v-if="notice" role="status">{{notice}}</p>
<section class="panel">
<h2>站点分组</h2>
<div class="form-grid">
<label>编辑分组<select v-model="groupID" @change="groupName=groups.find(g=>g.id===groupID)?.name||''">
<option value="">新建分组</option>
<option v-for="g in groups" :key="g.id" :value="g.id">{{g.name}}</option>
</select>
</label>
<label>分组名称<input v-model="groupName" maxlength="120" :disabled="!caps.manage_groups">
</label>
</div>
<button :disabled="!caps.manage_groups||busy||!groupName.trim()" @click="saveGroup">{{groupID?'保存分组':'创建分组'}}</button>
<ul>
<li v-for="g in groups" :key="g.id">{{g.name}} · 修订 {{g.revision}} <button :disabled="!caps.manage_groups||busy" @click="removeGroup(g)">删除分组</button>
</li>
</ul>
<p class="muted">分组管理需要管理员权限。删除分组保留站点，后端重新检查完整授权。</p>
</section>
<div class="resource-list">
<article v-for="site in sites" :key="site.id" class="panel">
<h2>{{site.name}}</h2>
<p class="mono">{{site.id}}</p>
<p>草稿修订 {{site.revision}} · 已发布修订 {{site.published_revision||'无'}}</p>
<p>{{site.draft.domains.join('、')}} · {{site.draft.enabled?'启用':'停用'}} · {{site.draft.maintenance.enabled?'维护响应':'正常路由'}}</p>
<button :data-testid="'edit-site-'+site.id" @click="edit(site)">{{canEdit?'编辑草稿':'查看配置'}}</button>
<details v-if="site.published">
<summary>已发布配置（运行实测见发布审阅）</summary>
<pre>{{JSON.stringify(site.published,null,2)}}</pre>
</details>
</article>
</div>
<form v-if="editing" ref="form" class="panel" @submit.prevent="save">
<h2>{{id?'站点草稿':'新建站点'}}</h2>
<p v-if="id" class="mono">{{id}} · 编辑基线修订 {{revision}}</p>
<fieldset :disabled="!canEdit||busy">
<div class="form-grid">
<label>站点名称<input v-model="name" required maxlength="120" :disabled="!!id">
</label>
<label>所属分组<select v-model="groupIDs" multiple>
<option v-for="g in groups" :key="g.id" :value="g.id" :disabled="!id&&!caps.create_site_group_ids.includes(g.id)">{{g.name}}</option>
</select>
</label>
</div>
<button v-if="id" type="button" @click="saveGroups">保存所属分组</button>
<label>域名（每行一个）<textarea ref="domainField" :value="config.domains.join('\n')" @input="setDomains" required rows="3"/>
</label>
<div class="form-grid">
<label class="check">
<input v-model="config.enabled" type="checkbox">启用站点</label>
<label class="check">
<input v-model="config.maintenance.enabled" type="checkbox">维护响应</label>
<label>维护状态<input v-model.number="config.maintenance.status" type="number" min="400" max="599" required>
</label>
<label>维护消息<input v-model="config.maintenance.message" maxlength="1024">
</label>
<label>默认目标组<select v-model="config.default_target.id">
<option :value="undefined">无默认目标（返回 503）</option>
<option v-if="config.default_target.id&&!targets.some(t=>t.id===config.default_target.id)" :value="config.default_target.id">当前共享目标（无完整查看权限）</option>
<option v-for="t in targets" :key="t.id" :value="t.id">{{t.config.name}}</option>
</select>
</label>
</div>
<h3>路径路由</h3>
<article v-for="(route,i) in config.routes" :key="i" class="subpanel">
<div class="form-grid">
<label>路径 {{i+1}}<input v-model="route.path" required pattern="/[^?#]*">
</label>
<label>匹配 {{i+1}}<select v-model="route.match">
<option value="prefix">前缀</option>
<option value="exact">精确</option>
</select>
</label>
<label>路径目标 {{i+1}}<select v-model="route.target.id" required>
<option v-if="route.target.id&&!targets.some(t=>t.id===route.target.id)" :value="route.target.id">当前共享目标（无完整查看权限）</option>
<option v-for="t in targets" :key="t.id" :value="t.id">{{t.config.name}}</option>
</select>
</label>
<label class="check">
<input v-model="route.strip_prefix" type="checkbox">去除前缀 {{i+1}}</label>
<label class="check">
<input type="checkbox" :checked="!!route.rate" @change="route.rate=($event.target as HTMLInputElement).checked?emptyRate():undefined">路径限流 {{i+1}}</label>
</div>
<rate-fields v-if="route.rate" :model="route.rate" :prefix="'路径 '+(i+1)+' '"/>
<button type="button" @click="config.routes.splice(i,1)">删除路径 {{i+1}}</button>
</article>
<button type="button" @click="config.routes.push({match:'prefix',path:'/',strip_prefix:false,target:{}})">添加路径</button>
<h3>站点限流（0 表示不限制）</h3>
<rate-fields :model="config.rate" prefix="站点 "/>
<h3>访问策略</h3>
<div class="form-grid">
<label>允许网络<textarea :value="config.access.allow.join('\n')" @input="config.access.allow=lines(($event.target as HTMLTextAreaElement).value)"/>
</label>
<label>拒绝网络<textarea :value="config.access.deny.join('\n')" @input="config.access.deny=lines(($event.target as HTMLTextAreaElement).value)"/>
</label>
<label>拒绝路径<textarea :value="config.access.deny_paths.join('\n')" @input="config.access.deny_paths=lines(($event.target as HTMLTextAreaElement).value)"/>
</label>
</div>
<h3>连接策略</h3>
<div class="form-grid">
<label>连接超时（秒）<input v-model.number="config.connection.connect_timeout_seconds" type="number" min="1" max="300" required>
</label>
<label>读取超时（秒）<input v-model.number="config.connection.read_timeout_seconds" type="number" min="1" max="3600" required>
</label>
<label>发送超时（秒）<input v-model.number="config.connection.send_timeout_seconds" type="number" min="1" max="3600" required>
</label>
<label>请求体上限（字节）<input v-model.number="config.connection.max_body_bytes" type="number" min="0" required>
</label>
<label class="check">
<input v-model="config.connection.websocket" type="checkbox">WebSocket</label>
<label class="check">
<input v-model="config.connection.sse" type="checkbox">SSE</label>
<label class="check">
<input v-model="config.connection.buffer_responses" type="checkbox">缓冲响应</label>
</div>
<h3>TLS 与来源</h3>
<material-fields v-model="config.entry_certificate" label="入口证书引用"/>
<div class="form-grid">
<label>Cloudflare 模式<select v-model="config.cloudflare.mode">
<option value="off">off</option>
<option value="proxied">proxied</option>
</select>
</label>
<label class="check">
<input v-model="config.cloudflare.require_origin_pull" type="checkbox">要求 Authenticated Origin Pull</label>
<label>可信代理网络<textarea :value="config.cloudflare.trusted_proxy_networks.join('\n')" @input="config.cloudflare.trusted_proxy_networks=lines(($event.target as HTMLTextAreaElement).value)"/>
</label>
<label>客户端验证<select v-model="config.client_verification.mode">
<option value="off">off</option>
<option value="optional">optional</option>
<option value="required">required</option>
</select>
</label>
<label>验证深度<input v-model.number="config.client_verification.depth" type="number" min="0" max="10" required>
</label>
<label>吊销检查<select v-model="config.client_verification.revocation">
<option value="">关闭</option>
<option value="crl">CRL</option>
<option value="ocsp">OCSP</option>
<option value="crl_ocsp">CRL + OCSP</option>
</select>
</label>
</div>
<material-fields v-model="config.client_verification.trust" label="客户端信任引用"/>
<p class="muted">当前材料提供方未就绪。引用只接受 unavailable；发布会明确拒绝不可用材料。Cloudflare provider 未就绪时不会假报就绪。</p>
<button type="submit">保存站点草稿</button>
</fieldset>
</form>
<section v-if="editing&&id" class="panel">
<h2>迁移检测</h2>
<p class="muted">只读检测显式入口，不修改 DNS、策略或客户端凭据。结果对应服务端修订，不能替代切换后的验收。</p>
<div class="form-grid">
<label>检测入口地址<input v-model="entry.address" placeholder="203.0.113.10:443">
</label>
<label>检测角色<select v-model="entry.role">
<option value="old">旧入口</option>
<option value="new">新入口</option>
</select>
</label>
<label>检测模式<select v-model="entry.mode">
<option value="direct">direct</option>
<option value="cloudflare">cloudflare</option>
</select>
</label>
<label>检测域名<input v-model="entry.domain">
</label>
<label>检测路径<input v-model="entry.path">
</label>
</div>
<button :disabled="busy" @click="preflight">运行迁移检测</button>
<p v-if="report" data-testid="preflight-result">修订 {{report.revision}} · {{report.result}} · {{report.reason||''}} · {{report.ready?'该入口检测通过':'未确认就绪'}}</p>
</section>
<button :disabled="busy" @click="perform(load)">刷新配置</button>
</section>
</template>
