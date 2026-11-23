<script setup lang="ts">
import Resources from '../certificates/Resources.vue';
</script>
<template><section><h1>凭据管理</h1><p class="muted">机构固定为 Let's Encrypt、ZeroSSL、Google 或受信内部标准 ACME 目录；不自动切换机构。所有修改重新核对当前权限、全部草稿和已发布引用，并要求一次性动态验证码。</p><Resources kind="account"/><Resources kind="credential"/></section></template>
