<script setup lang="ts">
import type { RatePolicy } from './contracts';
defineProps<{
    model: RatePolicy;
    prefix: string;
}>();
</script>
<template>
<div class="form-grid">
<label>{{prefix}}每秒请求<input v-model.number="model.requests_per_second" type="number" min="0" max="1000000" required>
</label>
<label>{{prefix}}突发请求<input v-model.number="model.burst" type="number" min="0" max="1000000" required>
</label>
<label>{{prefix}}并发连接<input v-model.number="model.connections" type="number" min="0" max="1000000" required>
</label>
<label>{{prefix}}限流状态<select v-model.number="model.status">
<option :value="429">429</option>
<option :value="503">503</option>
</select>
</label>
</div>
</template>
