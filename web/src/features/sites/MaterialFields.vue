<script setup lang="ts">
import type { MaterialRef } from './contracts';
const model = defineModel<MaterialRef | undefined>();
defineProps<{
    label: string;
}>();
</script>
<template>
<div>
<label class="check">
<input type="checkbox" :checked="!!model" @change="model=($event.target as HTMLInputElement).checked?{id:'',revision:1,status:'unavailable'}:undefined">{{label}}</label>
<div v-if="model" class="form-grid">
<label>{{label}} ID<input v-model="model.id" required pattern="[a-fA-F0-9-]{36}">
</label>
<label>{{label}}修订<input v-model.number="model.revision" type="number" min="1" required>
</label>
<label>{{label}}状态<select v-model="model.status">
<option value="unavailable">unavailable</option>
</select>
</label>
</div>
</div>
</template>
