<script setup lang="ts">
import { onMounted, ref, computed } from 'vue';
import { request } from '../../api/client';
import { all, clone, message, permissions, capabilities, emptyCapabilities } from '../sites/data';
import { newTarget, lines, type Target, type TargetConfig, type Revision, type Site } from '../sites/contracts';
import MaterialFields from '../sites/MaterialFields.vue';
const caps = ref(emptyCapabilities());
const { canEdit } = permissions(), items = ref<Target[]>([]), sites = ref<Site[]>([]), error = ref(''), notice = ref(''), busy = ref(false), editing = ref(false), id = ref(''), revision = ref(0), config = ref<TargetConfig>(newTarget()), form = ref<HTMLFormElement>();
const healthBudget = computed(() => Math.max(30, Math.ceil(config.value.members.length / 8) * config.value.health.timeout_seconds + 5));
async function load() { [items.value, sites.value] = await Promise.all([all<Target>('/targets'), all<Site>('/sites')]); caps.value = await capabilities(); }
const affected = computed(() => sites.value.filter(s => [s.draft, s.published].some(c => c && (c.default_target.id === id.value || c.routes.some(r => r.target.id === id.value)))));
async function perform(fn: () => Promise<void>) { busy.value = true; error.value = ''; notice.value = ''; try {
    await fn();
}
catch (e) {
    caps.value = emptyCapabilities();
    error.value = message(e);
}
finally {
    busy.value = false;
} }
function edit(t?: Target) { id.value = t?.id || ''; revision.value = t?.revision || 0; config.value = t ? clone(t.config) : newTarget(); config.value.tls_server_name_mode ??= ''; editing.value = true; error.value = ''; notice.value = ''; }
async function save() { if (!form.value?.reportValidity())
    return; await perform(async () => { config.value.allowed_networks = config.value.allowed_networks.map(v => v.trim()).filter(Boolean); const out = await request<Revision>('/targets' + (id.value ? '/' + id.value : ''), { config: config.value, expected_revision: revision.value }, id.value ? 'PUT' : 'POST'); id.value = out.resource_id; revision.value = out.number; await load(); notice.value = '目标草稿已保存'; }); }
onMounted(() => void perform(load));
</script>
<template>
<section>
<div class="section-heading">
<div>
<h1>目标组</h1>
<p class="muted">共享目标变更需要全部引用站点授权。此处只列出当前可完整查看的目标组。</p>
</div>
<button :disabled="!caps.create_target||busy" @click="edit()">新建目标组</button>
</div>
<p v-if="error" role="alert">{{error}}</p>
<p v-if="notice" role="status">{{notice}}</p>
<div class="resource-list">
<article v-for="item in items" :key="item.id" class="panel">
<h2>{{item.config.name}}</h2>
<p class="mono">{{item.id}}</p>
<p>草稿修订 {{item.revision}} · 已发布修订 {{item.published_revision||'无'}}</p>
<button :data-testid="'edit-target-'+item.id" @click="edit(item)">{{canEdit?'编辑目标草稿':'查看目标配置'}}</button>
<details v-if="item.published">
<summary>已发布目标配置</summary>
<pre>{{JSON.stringify(item.published,null,2)}}</pre>
</details>
</article>
</div>
<form v-if="editing" ref="form" class="panel" @submit.prevent="save">
<h2>{{id?'目标草稿':'新建目标组'}}</h2>
<p v-if="id" class="mono">{{id}} · 修订 {{revision}}</p>
<section v-if="id" class="subpanel">
<h3>共享影响（当前可见引用）</h3>
<ul>
<li v-for="s in affected" :key="s.id">{{s.name}} · {{s.id}}</li>
</ul>
<p class="muted">包含草稿和已发布引用。保存时后端重新检查引用图及全部站点授权；发布时还须审阅完整候选闭包。</p>
</section>
<fieldset :disabled="!canEdit||busy">
<div class="form-grid">
<label>目标组名称<input v-model="config.name" maxlength="120" required>
</label>
<label>上游协议<select v-model="config.protocol">
<option value="http">HTTP</option>
<option value="https">HTTPS</option>
</select>
</label>
<label>HTTP Host<input v-model="config.http_host" placeholder="business.example">
</label>
<label>TLS SNI 发送<select v-model="config.tls_server_name_mode"><option value="">默认发送 SNI</option><option value="send">发送 SNI</option><option value="verify_only">仅验证名称（专用原生 mTLS 监听器）</option></select></label>
<label>TLS 名称模式<select v-model="config.tls_name_mode">
<option value="">HTTP 无 TLS</option>
<option value="fixed">固定名称</option>
<option value="member">按成员</option>
</select>
</label>
<label>固定 TLS 名称<input v-model="config.tls_name" placeholder="origin.example">
</label>
</div>
<h3>连接成员</h3>
<p class="muted">连接地址、HTTP Host 与 TLS 验证名称独立。HTTP 配置的 TLS 字段应留空；HTTPS 必须有信任引用且保留证书验证。</p>
<article v-for="(member,i) in config.members" :key="i" class="subpanel">
<div class="form-grid">
<label>{{i===0?'连接地址':'连接地址 '+(i+1)}}<input v-model="member.address" required placeholder="10.0.0.10 或 origin.example">
</label>
<label>{{i===0?'端口':'端口 '+(i+1)}}<input v-model.number="member.port" type="number" min="1" max="65535" required>
</label>
<label>权重 {{i+1}}<input v-model.number="member.weight" type="number" min="1" max="1000" required>
</label>
<label>成员 TLS 名称 {{i+1}}<input v-model="member.tls_name">
</label>
</div>
<button type="button" :disabled="config.members.length<=1" @click="config.members.splice(i,1)">删除成员 {{i+1}}</button>
</article>
<button type="button" :disabled="config.members.length>=100" @click="config.members.push({address:'',port:80,weight:1,tls_name:''})">添加成员</button>
<label>允许连接网络<textarea :value="config.allowed_networks.join('\n')" @input="config.allowed_networks=lines(($event.target as HTMLTextAreaElement).value)" required placeholder="10.0.0.0/24"/>
</label>
<material-fields v-model="config.trust" label="上游信任引用"/>
<material-fields v-model="config.client_certificate" label="上游客户端证书引用"/>
<p class="muted">证书材料提供方当前未就绪，引用状态为 unavailable；服务端不会将占位材料发布。</p>
<h3>健康检查</h3>
<div class="form-grid">
<label class="check">
<input v-model="config.health.enabled" type="checkbox">启用健康检查</label>
<label>健康检查 HTTP Host<input v-model="config.health.http_host">
</label>
<label>健康检查路径<input v-model="config.health.path" pattern="/[^?#]*" required>
</label>
<label>检查间隔（秒）<input v-model.number="config.health.interval_seconds" type="number" min="1" max="3600" required>
</label>
<label>检查超时（秒）<input v-model.number="config.health.timeout_seconds" type="number" min="1" :max="Math.min(60,config.health.interval_seconds)" required>
</label>
<label>失败阈值<input v-model.number="config.health.unhealthy_threshold" type="number" min="1" max="100" required>
</label>
<label>成功阈值<input v-model.number="config.health.healthy_threshold" type="number" min="1" max="100" required>
</label>
</div>
<p class="muted">默认间隔 5 秒、超时 2 秒、失败 3 次、成功 2 次。运行预算按解析后端点数计算：8 并发、至少 30 秒、最多 65 秒。按当前成员数估算 {{healthBudget}} 秒；DNS 多地址可能增加端点数，最终由后端判断。</p>
<p v-if="config.health.enabled&&healthBudget>65" role="alert">仅当前成员数的最低运行预算已超过 65 秒，请减少成员或超时。解析后的实际端点数仍由后端重新核验。</p>
<button type="submit">保存目标草稿</button>
</fieldset>
</form>
<button :disabled="busy" @click="perform(load)">刷新目标组</button>
</section>
</template>
