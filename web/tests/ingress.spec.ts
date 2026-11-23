import { test, expect } from '@playwright/test';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createHmac } from 'node:crypto';
import { execFileSync } from 'node:child_process';
const fixture = JSON.parse(readFileSync(process.env.GATEBEAM_WEB_FIXTURE!, 'utf8'));
const faultPreparationTimeout = process.env.GATEBEAM_ACCEPTANCE_EXECUTION === 'software-emulated-vm' ? 120000 : 10000;
function code(uri: string, offset = 0) { let bits = ''; for (const c of new URL(uri).searchParams.get('secret')!)
    bits += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c).toString(2).padStart(5, '0'); const bytes = Buffer.from((bits.match(/.{8}/g) || []).map(v => parseInt(v, 2))); const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + offset)); const digest = createHmac('sha1', bytes).update(counter).digest(), n = digest[digest.length - 1]! & 15; return ((digest.readUInt32BE(n) & 0x7fffffff) % 1000000).toString().padStart(6, '0'); }
test('真实入口：草稿隔离、共享权限、选站发布、恢复结果和迁移检测', async ({ page, context }) => {
    console.log(`Ingress browser: ${context.browser()?.version()}`);
    await page.goto('/enroll');
    await page.getByLabel('一次性绑定资料').fill(JSON.stringify(fixture.enrollment));
    await page.getByRole('button', { name: '读取绑定资料' }).click();
    await page.getByLabel('设置密码').fill(fixture.password);
    await page.getByLabel('动态验证码', { exact: true }).fill(code(fixture.enrollment.provisioning_uri));
    await page.getByRole('button', { name: '完成绑定' }).click();
    await page.getByRole('button', { name: '已保存，关闭并登录' }).click();
    await page.getByLabel('账号', { exact: true }).fill(fixture.name);
    await page.getByLabel('密码', { exact: true }).fill(fixture.password);
    await page.getByRole('button', { name: '继续验证' }).click();
    await page.getByLabel('动态验证码', { exact: true }).fill(code(fixture.enrollment.provisioning_uri, 1));
    await page.getByRole('button', { name: '登录', exact: true }).click();
    await expect(page.getByRole('heading', { name: '会话概览' })).toBeVisible();
    await page.getByRole('link', { name: '站点配置', exact: true }).click();
    await expect(page.getByRole('heading', { name: '站点配置', exact: true })).toBeVisible();
    await page.getByLabel('分组名称').fill('迁移组');
    await page.getByRole('button', { name: '创建分组', exact: true }).click();
    await expect(page.getByText('分组已保存')).toBeVisible();
    await page.getByRole('link', { name: '目标组', exact: true }).click();
    await page.getByRole('button', { name: '新建目标组', exact: true }).click();
    await page.getByLabel('目标组名称').fill('共享后端');
    await page.getByLabel('连接地址', { exact: true }).fill(fixture.upstreamAddress);
    await page.getByLabel('端口', { exact: true }).fill('80');
    await page.getByLabel('HTTP Host', { exact: true }).fill('backend.test');
    await page.getByLabel('允许连接网络').fill(fixture.upstreamNetwork);
    await page.getByLabel('权重 1', { exact: true }).fill('3');
    await page.getByLabel('检查间隔（秒）').fill('7');
    await page.getByLabel('检查超时（秒）').fill('3');
    await page.getByLabel('失败阈值').fill('4');
    await page.getByLabel('成功阈值').fill('3');
    await page.getByRole('button', { name: '保存目标草稿' }).click();
    await expect(page.getByText('目标草稿已保存')).toBeVisible();
    const targets = (await (await page.request.get('/targets')).json()).items;
    const target = targets[0];
    expect(target.config.members[0].weight).toBe(3);
    expect(target.config.health).toMatchObject({ interval_seconds: 7, timeout_seconds: 3, unhealthy_threshold: 4, healthy_threshold: 3 });
    expect(target.config.http_host).toBe('backend.test');
    expect(target.config.members[0].address).toBe(fixture.upstreamAddress);
    expect(target.config.tls_name).toBe('');
    async function create(name: string, domain: string) { await page.getByRole('link', { name: '站点配置', exact: true }).click(); await page.getByRole('button', { name: '新建站点' }).click(); await page.getByLabel('站点名称').fill(name); await page.getByLabel('域名（每行一个）').fill('invalid host'); await page.getByRole('button', { name: '保存站点草稿' }).click(); await expect(page.getByLabel('域名（每行一个）')).toBeFocused(); await page.getByLabel('域名（每行一个）').fill(domain); await page.getByLabel('默认目标组').selectOption(target.id);
        if(domain==='alpha.test'){
          await page.getByRole('button',{name:'添加路径'}).click();
          await page.getByLabel('路径 1',{exact:true}).fill('/api/');
          await page.getByLabel('路径目标 1').selectOption(target.id);
          await page.getByLabel('去除前缀 1').check();
          await page.getByLabel('路径限流 1').check();
          await page.getByLabel('路径 1 每秒请求').fill('100');
          await page.getByLabel('路径 1 突发请求').fill('10');
          await page.getByLabel('路径 1 并发连接').fill('20');
          await page.getByLabel('站点 每秒请求').fill('200');
          await page.getByLabel('站点 突发请求').fill('40');
          await page.getByLabel('站点 并发连接').fill('50');
        }
        await page.getByLabel('所属分组').selectOption({ label: '迁移组' }); await page.getByRole('button', { name: '保存站点草稿' }).click(); await expect.poll(async () => [...(await page.getByRole('status').allTextContents()), ...(await page.getByRole('alert').allTextContents()), ...(await page.locator('form :invalid').evaluateAll(nodes => nodes.map(n => (n as HTMLInputElement).validationMessage)))].join(';')).toBe('站点草稿已保存'); }
    await create('站点甲', 'alpha.test');
    await create('隐藏站点乙', 'beta.test');
    // Every delayed response below is fetched from the genuine API. No mutation receipt or publish success is fabricated.
    const csrfProof=await page.evaluate(()=>sessionStorage.getItem('gatebeam.csrf'));
    const headers={Origin:fixture.origin,'X-CSRF-Token':csrfProof!};
    const siteList=async()=> (await(await page.request.get('/sites')).json()).items;
    const openSite=async(siteID:string)=>{await page.getByRole('link',{name:'站点配置',exact:true}).click();await page.getByRole('button',{name:'刷新配置',exact:true}).click();await expect(page.getByRole('button',{name:'刷新配置',exact:true})).toBeEnabled();await page.getByTestId('edit-site-'+siteID).click()};
    const alphaID=(await siteList()).find((s:any)=>s.name==='站点甲').id;
    const betaID=(await siteList()).find((s:any)=>s.name==='隐藏站点乙').id;
    const frame=()=>page.evaluate(()=>new Promise<void>(resolve=>requestAnimationFrame(()=>requestAnimationFrame(()=>resolve()))));
    await test.step('真实第二写入者：草稿与分组保存不能采纳未审阅 head',async()=>{
        for(const kind of ['draft','groups']){
            await openSite(alphaID);
            const original=await(await page.request.get('/sites/'+alphaID)).json();
            let intercepted=false;
            const path='/sites/'+alphaID+'/'+kind;
            await page.route('**'+path,async route=>{
                if(route.request().method()!=='PUT'||intercepted){await route.continue();return}
                intercepted=true;
                const receipt=await route.fetch();expect(receipt.status()).toBe(kind==='draft'?200:204);
                const current=await(await page.request.get('/sites/'+alphaID)).json();
                const config=structuredClone(current.draft);config.maintenance.message='unseen-'+kind+'-writer';config.connection.read_timeout_seconds=77;
                const second=await page.request.put('/sites/'+alphaID+'/draft',{headers,data:{config,expected_revision:current.revision}});expect(second.status()).toBe(200);
                await route.fulfill({response:receipt});
            });
            if(kind==='draft')await page.getByLabel('维护消息').fill('first-writer');
            await page.getByRole('button',{name:kind==='draft'?'保存站点草稿':'保存所属分组',exact:true}).click();
            await expect(page.getByText(kind==='draft'?'站点草稿已保存':'所属分组已保存',{exact:true})).toBeVisible();
            await page.unroute('**'+path);
            expect(await page.locator('form.panel > p.mono').textContent()).toContain('编辑基线修订 '+(original.revision+1));
            const next=page.waitForResponse(r=>new URL(r.url()).pathname===path&&r.request().method()==='PUT');
            await page.getByRole('button',{name:kind==='draft'?'保存站点草稿':'保存所属分组',exact:true}).click();
            expect.soft((await next).status(),'next '+kind+' save must use its own receipt revision, not '+(original.revision+2)).toBe(409);
            const current=await(await page.request.get('/sites/'+alphaID)).json();
            expect.soft(current.draft.maintenance.message).toBe('unseen-'+kind+'-writer');
        }
    });
    await test.step('迟到的 A 保存回执不能更换 B 表单基线',async()=>{
        for(const kind of ['draft','groups']){
            await openSite(alphaID);
            let held!:()=>void,ready!:()=>void;
            const hold=new Promise<void>(r=>held=r),seen=new Promise<void>(r=>ready=r);
            const path='/sites/'+alphaID+'/'+kind;
            await page.route('**'+path,async route=>{const response=await route.fetch();expect(response.status()).toBe(kind==='draft'?200:204);ready();await hold;await route.fulfill({response})});
            await page.getByRole('button',{name:kind==='draft'?'保存站点草稿':'保存所属分组',exact:true}).click();await seen;
            await page.getByTestId('edit-site-'+betaID).click();
            const beta=await(await page.request.get('/sites/'+betaID)).json();
            const changed=structuredClone(beta.draft);changed.connection.read_timeout_seconds=kind==='draft'?101:102;
            expect((await page.request.put('/sites/'+betaID+'/draft',{headers,data:{config:changed,expected_revision:beta.revision}})).status()).toBe(200);
            held();await expect(page.getByRole('button',{name:'刷新配置',exact:true})).toBeEnabled();await frame();await page.unroute('**'+path);
            expect.soft(await page.getByLabel('读取超时（秒）').inputValue()).toBe(String(beta.draft.connection.read_timeout_seconds));
            const next=page.waitForResponse(r=>new URL(r.url()).pathname==='/sites/'+betaID+'/draft'&&r.request().method()==='PUT');
            await page.getByRole('button',{name:'保存站点草稿',exact:true}).click();
            expect.soft((await next).status(),'A '+kind+' completion must not adopt a newer B guard').toBe(409);
            expect.soft((await(await page.request.get('/sites/'+betaID)).json()).draft.connection.read_timeout_seconds).toBe(changed.connection.read_timeout_seconds);
        }
    });
    await test.step('同一站点的新编辑代次也不能接收旧保存回执',async()=>{
        for(const kind of ['draft','groups']){
            await openSite(alphaID);
            let release!:()=>void,ready!:()=>void;
            const hold=new Promise<void>(r=>release=r),seen=new Promise<void>(r=>ready=r);
            const path='/sites/'+alphaID+'/'+kind;
            await page.route('**'+path,async route=>{const response=await route.fetch();expect(response.status()).toBe(kind==='draft'?200:204);ready();await hold;await route.fulfill({response})});
            if(kind==='draft')await page.getByLabel('维护消息').fill('receipt-owned-old-generation');
            await page.getByRole('button',{name:kind==='draft'?'保存站点草稿':'保存所属分组',exact:true}).click();await seen;
            await page.getByTestId('edit-site-'+alphaID).click();
            release();await expect(page.getByRole('button',{name:'刷新配置',exact:true})).toBeEnabled();await frame();await page.unroute('**'+path);
            const next=page.waitForResponse(r=>new URL(r.url()).pathname===path&&r.request().method()==='PUT');
            await page.getByRole('button',{name:kind==='draft'?'保存站点草稿':'保存所属分组',exact:true}).click();
            expect((await next).status(),'old receipt must not advance the new edit generation').toBe(409);
        }
    });
    await test.step('正常分组保存后继续保存草稿，不产生虚假冲突',async()=>{
        await openSite(alphaID);
        const before=await(await page.request.get('/sites/'+alphaID)).json();
        await page.getByRole('button',{name:'保存所属分组',exact:true}).click();await expect(page.getByText('所属分组已保存',{exact:true})).toBeVisible();
        await page.getByLabel('维护消息').fill('own-group-then-draft');
        const saved=page.waitForResponse(r=>r.request().method()==='PUT'&&new URL(r.url()).pathname==='/sites/'+alphaID+'/draft');
        await page.getByRole('button',{name:'保存站点草稿',exact:true}).click();expect((await saved).status()).toBe(200);await expect(page.getByText('站点草稿已保存',{exact:true})).toBeVisible();
        const after=await(await page.request.get('/sites/'+alphaID)).json();expect(after.revision).toBe(before.revision+2);expect(after.draft.maintenance.message).toBe('own-group-then-draft');
    });
    await test.step('候选 A/B diff、prepare 与旧 poll 的响应归属和审阅身份',async()=>{
        const current=await siteList(),aSite=current.find((s:any)=>s.id===alphaID),bSite=current.find((s:any)=>s.id===betaID);
        const prepareAPI=async(site:any)=>{const response=await page.request.post('/releases/prepare',{headers,data:{site_ids:[site.id],expected:{['site:'+site.id]:site.revision,['target:'+target.id]:target.revision}}});expect(response.status()).toBe(201);return response.json()};
        const a=await prepareAPI(aSite),b=await prepareAPI(bSite);
        await page.getByRole('link',{name:'发布审阅',exact:true}).click();
        const panel=page.locator('section.panel').filter({has:page.getByRole('heading',{name:'候选差异',exact:true})});
        let releaseA!:()=>void,seenA!:()=>void;const holdA=new Promise<void>(r=>releaseA=r),aReady=new Promise<void>(r=>seenA=r);
        await page.route('**/releases/'+a.id+'/diff',async route=>{const response=await route.fetch();seenA();await holdA;await route.fulfill({response})});
        await page.getByRole('button',{name:a.id,exact:true}).click();await aReady;
        await page.getByRole('button',{name:b.id,exact:true}).click();await expect(panel).toContainText(b.input_digest);
        await page.getByRole('checkbox',{name:'我已审阅共享影响及修订差异'}).check();
        const late=page.waitForResponse(r=>r.url().endsWith('/releases/'+a.id+'/diff'));releaseA();await late;await frame();
        expect.soft(await panel.textContent()).toContain(b.input_digest);expect.soft(await panel.textContent()).not.toContain(a.input_digest);
        await page.unroute('**/releases/'+a.id+'/diff');
        // A delayed prepare response must also lose to the newer review selection B.
        await page.getByTestId('select-site-'+alphaID).check();await page.getByTestId('select-target-'+target.id).check();
        let releasePrepare!:()=>void,seenPrepare!:()=>void;const prepareHold=new Promise<void>(r=>releasePrepare=r),prepareReady=new Promise<void>(r=>seenPrepare=r);
        await page.route('**/releases/prepare',async route=>{const response=await route.fetch();seenPrepare();await prepareHold;await route.fulfill({response})});
        await page.getByRole('button',{name:'生成候选并校验'}).click();await prepareReady;
        await page.getByRole('button',{name:b.id,exact:true}).click();await expect(panel).toContainText(b.input_digest);
        await page.getByRole('checkbox',{name:'我已审阅共享影响及修订差异'}).check();
        const latePrepare=page.waitForResponse(r=>r.url().endsWith('/releases/prepare')&&r.request().method()==='POST');releasePrepare();await latePrepare;await frame();
        expect.soft(await panel.textContent()).toContain(b.input_digest);await page.unroute('**/releases/prepare');
        // Pause only the owned real consumer so the API truth is deterministically queued.
        execFileSync('docker',['pause',fixture.edgeContainer],{timeout:5000,stdio:'ignore'});
        try{
            expect((await page.request.post('/releases/'+a.id+'/publish',{headers,data:{}})).status()).toBe(202);
            let count=0,releasePoll!:()=>void,seenPoll!:()=>void;const pollHold=new Promise<void>(r=>releasePoll=r),pollReady=new Promise<void>(r=>seenPoll=r);
            await page.route('**/releases/'+a.id,async route=>{const response=await route.fetch();if(++count===2){seenPoll();await pollHold}await route.fulfill({response})});
            await page.getByRole('button',{name:a.id,exact:true}).click();await expect(page.getByTestId('release-state')).toContainText('已排队');await pollReady;
            await page.getByRole('button',{name:b.id,exact:true}).click();await expect(panel).toContainText(b.input_digest);await page.getByRole('checkbox',{name:'我已审阅共享影响及修订差异'}).check();
            const latePoll=page.waitForResponse(r=>r.url().endsWith('/releases/'+a.id));releasePoll();await latePoll;await frame();
            expect.soft(await panel.textContent()).toContain(b.input_digest);expect.soft(await page.getByTestId('release-state').textContent()).toContain('候选已准备');
            await page.unroute('**/releases/'+a.id);
            // Re-select B after the assertions so the genuine publish request can be inspected even on RED.
            await page.getByRole('button',{name:b.id,exact:true}).click();await expect(panel).toContainText(b.input_digest);await page.getByRole('checkbox',{name:'我已审阅共享影响及修订差异'}).check();
            const sent:string[]=[];const record=(request:any)=>{if(request.method()==='POST'&&/\/releases\/[^/]+\/publish$/.test(new URL(request.url()).pathname))sent.push(new URL(request.url()).pathname)};page.on('request',record);
            let releasePublish!:()=>void,seenPublish!:()=>void;const publishHold=new Promise<void>(r=>releasePublish=r),publishReady=new Promise<void>(r=>seenPublish=r);
            await page.route('**/releases/'+b.id+'/publish',async route=>{const response=await route.fetch();expect(response.status()).toBe(202);seenPublish();await publishHold;await route.fulfill({response})});
            await page.getByRole('button',{name:'发布此候选',exact:true}).click();await publishReady;
            await page.getByRole('button',{name:a.id,exact:true}).click();await expect(panel).toContainText(a.input_digest);
            const capturedRead=page.waitForRequest(r=>r.method()==='GET'&&r.url().endsWith('/releases/'+b.id));
            const latePublish=page.waitForResponse(r=>r.url().endsWith('/releases/'+b.id+'/publish'));releasePublish();await latePublish;await capturedRead;await frame();
            expect(await panel.textContent()).toContain(a.input_digest);await expect(page.getByRole('button',{name:'发布此候选',exact:true})).toBeDisabled();
            page.off('request',record);expect(sent).toEqual(['/releases/'+b.id+'/publish']);await page.unroute('**/releases/'+b.id+'/publish');
        }finally{execFileSync('docker',['unpause',fixture.edgeContainer],{timeout:5000,stdio:'ignore'})}
        await expect.poll(async()=>{const aState=(await(await page.request.get('/releases/'+a.id)).json()).state,bState=(await(await page.request.get('/releases/'+b.id)).json()).state;return ['succeeded','failed'].includes(aState)&&['succeeded','failed'].includes(bState)},{timeout:18000}).toBe(true);
        await page.getByRole('link',{name:'站点配置',exact:true}).click();
    });
    let sites = (await (await page.request.get('/sites')).json()).items;
    const alpha = sites.find((s: any) => s.name === '站点甲'), beta = sites.find((s: any) => s.name === '隐藏站点乙');
    async function prepare(siteIDs: string[], targetIDs: string[] = []) { await page.getByRole('link', { name: '发布审阅', exact: true }).click(); for (const id of siteIDs)
        await page.getByTestId('select-site-' + id).check(); for (const id of targetIDs)
        await page.getByTestId('select-target-' + id).check(); await page.getByRole('button', { name: '生成候选并校验' }).click(); await expect(page.getByRole('heading', { name: '候选差异' })).toBeVisible(); }
    async function publish() { await page.getByRole('checkbox', { name: '我已审阅共享影响及修订差异' }).check(); await page.getByRole('button', { name: '发布此候选', exact: true }).click(); await expect(page.getByTestId('release-state')).toContainText('已验证成功', { timeout: 18000 }); }
    await prepare([alpha.id, beta.id], [target.id]);
    await expect(page.getByTestId('candidate-changes')).toContainText('target');
    await publish();
    const firstReleaseID=(await(await page.request.get('/releases')).json()).items[0].id;
    await test.step('逐节点结果不能把部分成功或隔离节点显示为全部生效',async()=>{
        let degraded=false;
        const a='11111111-1111-4111-8111-111111111111',b='22222222-2222-4222-8222-222222222222';
        await page.route('**/releases/'+firstReleaseID,async route=>{
            const response=await route.fetch();const value=await response.json();
            value.effective=false;
            value.node_progress={expected:2,succeeded:degraded?2:1,failed:degraded?0:1,state:degraded?'degraded':'partial_success',complete:false,degraded,nodes:[
                {node:{id:a,epoch:1},release_id:firstReleaseID,state:'succeeded',node_state:'active',artifact_id:'a'.repeat(64),generation:'generation-a',observed_at:new Date().toISOString()},
                {node:{id:b,epoch:1},release_id:firstReleaseID,state:degraded?'succeeded':'failed',node_state:degraded?'revoked':'active',artifact_id:degraded?'b'.repeat(64):'',generation:degraded?'generation-b':'',observed_at:new Date().toISOString()},
            ]};
            await route.fulfill({response,json:value});
        });
        await page.getByRole('button',{name:firstReleaseID,exact:true}).click();
        await expect(page.getByTestId('release-state')).toContainText('部分成功');
        await expect(page.getByTestId('node-release-progress')).toContainText('1 / 2');
        await expect(page.getByTestId('node-release-progress')).toContainText(b);
        degraded=true;
        await page.getByRole('button',{name:firstReleaseID,exact:true}).click();
        await expect(page.getByTestId('release-state')).toContainText('降级');
        await expect(page.getByTestId('node-release-progress')).toContainText('已撤销');
        await page.unroute('**/releases/'+firstReleaseID);
    });

    async function entry(domain: string,path='/') { const r = await page.request.get(fixture.edgeURL + path, { headers: { Host: domain } }); return { status: r.status(), body: await r.text() }; }
    expect((await entry('alpha.test')).body).toContain('Welcome to nginx');
    expect((await entry('alpha.test','/api/')).body).toContain('Welcome to nginx');
    expect(alpha.draft.rate).toMatchObject({requests_per_second:200,burst:40,connections:50});
    expect(alpha.draft.routes[0]).toMatchObject({path:'/api/',strip_prefix:true,rate:{requests_per_second:100,burst:10,connections:20}});
    // Saving changes only the draft. Real edge continues routing the published head.
    await page.getByRole('link', { name: '站点配置', exact: true }).click();
    await page.getByTestId('edit-site-' + alpha.id).click();
    await page.getByLabel('维护响应').check();
    await page.getByLabel('维护消息').fill('alpha-maintenance');
    await page.getByRole('button', { name: '保存站点草稿' }).click();
    await expect(page.getByText('站点草稿已保存')).toBeVisible();
    expect((await entry('alpha.test')).body).toContain('Welcome to nginx');
    await page.getByTestId('edit-site-' + beta.id).click();
    await page.getByLabel('维护响应').check();
    await page.getByLabel('维护消息').fill('unselected-beta-draft');
    await page.getByRole('button', { name: '保存站点草稿' }).click();
    await expect(page.getByText('站点草稿已保存')).toBeVisible();
    await prepare([alpha.id]);
    await expect(page.getByTestId('candidate-changes')).not.toContainText(beta.id);
    await publish();
    expect((await entry('alpha.test')).status).toBe(503);
    expect((await entry('alpha.test')).body).toContain('alpha-maintenance');
    expect((await entry('beta.test')).body).toContain('Welcome to nginx');
    sites = (await (await page.request.get('/sites')).json()).items;
    expect(sites.find((s: any) => s.id === beta.id).published.maintenance.enabled).toBe(false);
    await page.getByRole('button',{name:firstReleaseID,exact:true}).click();await expect(page.getByTestId('release-state')).toContainText('此发布不是当前数据库确认的版本');
    // Provider-unavailable is a measured contract response, never a successful CF probe.
    await page.getByRole('link', { name: '站点配置', exact: true }).click();
    await page.getByTestId('edit-site-' + alpha.id).click();
    await page.getByLabel('检测入口地址').fill('203.0.113.10:443');
    await page.getByLabel('检测模式').selectOption('cloudflare');
    await page.getByRole('button', { name: '运行迁移检测' }).click();
    await expect(page.getByTestId('preflight-result')).toContainText('cloudflare_provider_unavailable');
    // Missing trusted CF ranges compile the existing native fail-closed policy.
    // This is verified configuration application, not a successful Cloudflare probe.
    await page.getByLabel('Cloudflare 模式').selectOption('proxied');
    await page.getByRole('button', { name: '保存站点草稿' }).click();
    await expect(page.getByText('站点草稿已保存')).toBeVisible();
    await prepare([alpha.id]);
    await page.getByRole('checkbox', { name: '我已审阅共享影响及修订差异' }).check();
    await page.getByRole('button', { name: '发布此候选', exact: true }).click();
    await expect(page.getByTestId('release-state')).toContainText('已验证成功', { timeout: 18000 });
    expect((await entry('alpha.test')).status).toBe(403);
    expect((await entry('alpha.test')).body).not.toContain('alpha-maintenance');
    // Restore the prior manual maintenance policy through a normal publication
    // before testing post-activation native faults and verified restoration.
    await page.getByRole('link', { name: '站点配置', exact: true }).click();
    await page.getByTestId('edit-site-' + alpha.id).click();
    await page.getByLabel('Cloudflare 模式').selectOption('off');
    await page.getByRole('button', { name: '保存站点草稿' }).click();
    await expect(page.getByText('站点草稿已保存')).toBeVisible();
    await prepare([alpha.id]);
    await publish();
    expect((await entry('alpha.test')).status).toBe(503);
    expect((await entry('alpha.test')).body).toContain('alpha-maintenance');
    // Explicit test-only native boundary faults; real candidate activation, restoration and route probes.
    writeFileSync(fixture.faultFile, 'restored', { mode: 0o666 });
    writeFileSync(fixture.faultSignal, 'start', { mode: 0o600 });
    // Prepare the owned fault injector before starting the publication/recovery assertions.
    await expect.poll(() => existsSync(fixture.faultReady) && existsSync(fixture.faultURLFile), { timeout: faultPreparationTimeout }).toBe(true);
    fixture.edgeURL = readFileSync(fixture.faultURLFile, 'utf8');
    await page.getByRole('link', { name: '站点配置', exact: true }).click();
    await page.getByTestId('edit-site-' + alpha.id).click();
    await page.getByLabel('Cloudflare 模式').selectOption('off');
    await page.getByLabel('维护消息').fill('injected-candidate-one');
    await page.getByRole('button', { name: '保存站点草稿' }).click();
    await expect(page.getByText('站点草稿已保存')).toBeVisible();
    await prepare([alpha.id]);
    await page.getByRole('checkbox', { name: '我已审阅共享影响及修订差异' }).check();
    await page.getByRole('button', { name: '发布此候选', exact: true }).click();
    await expect(page.getByTestId('release-state')).toContainText('已验证恢复', { timeout: 15000 });
    expect((await entry('alpha.test')).body).toContain('alpha-maintenance');
    writeFileSync(fixture.faultFile, 'restore_failed', { mode: 0o666 });
    await page.getByRole('link', { name: '站点配置', exact: true }).click();
    await page.getByTestId('edit-site-' + alpha.id).click();
    await page.getByLabel('维护消息').fill('injected-candidate-two');
    await page.getByRole('button', { name: '保存站点草稿' }).click();
    await expect(page.getByText('站点草稿已保存')).toBeVisible();
    await prepare([alpha.id]);
    await page.getByRole('checkbox', { name: '我已审阅共享影响及修订差异' }).check();
    await page.getByRole('button', { name: '发布此候选', exact: true }).click();
    await expect(page.getByTestId('release-state')).toContainText('恢复失败', { timeout: 15000 });
    await expect(page.getByTestId('release-state')).not.toContainText('已验证恢复');
    expect((await entry('alpha.test')).body).toContain('injected-candidate-two');
    // Resolve the owned injected failure with real current-security Recover before teardown.
    writeFileSync(fixture.recoverSignal,'recover',{mode:0o600});await expect.poll(()=>existsSync(fixture.recoveredSignal),{timeout:10000}).toBe(true);
    expect((await entry('alpha.test')).body).toContain('alpha-maintenance');
    await expect(page.getByTestId('release-state')).toContainText('恢复失败');
    // Real PostgreSQL history: an older succeeded authorized release behind
    // 105 newer denied candidates must survive an entirely empty first page.
    const historySiteResponse = await page.request.post('/sites', {headers, data:{name:'历史可见站点',config:{enabled:true,domains:['history-visible.test'],maintenance:{enabled:true,status:503,message:'history'}}}});
    expect(historySiteResponse.status()).toBe(201);
    const historyCreated = await historySiteResponse.json();
    const historySite = await(await page.request.get('/sites/'+historyCreated.resource_id)).json();
    const historicalResponse=await page.request.post('/releases/prepare',{headers,data:{site_ids:[historySite.id],expected:{['site:'+historySite.id]:historySite.revision}}});
    expect(historicalResponse.status()).toBe(201);
    const historical=await historicalResponse.json();
    expect((await page.request.post('/releases/'+historical.id+'/publish',{headers,data:{}})).status()).toBe(202);
    await expect.poll(async()=>(await(await page.request.get('/releases/'+historical.id)).json()).state,{timeout:15000}).toBe('succeeded');
    // Change the owned account authority through the existing file fixture, not a product endpoint.
    writeFileSync(fixture.scopeSignal, JSON.stringify({ site_id: alpha.id, history_site_id: historySite.id, history_hidden_site_id: beta.id }), { mode: 0o600 });
    await expect.poll(async () => (await (await page.request.get('/auth/session')).json()).role).toBe('publisher');
    await page.getByRole('link', { name: '目标组', exact: true }).click();
    await expect(page.getByRole('button', { name: '刷新目标组' })).toBeEnabled();
    await expect(page.getByRole('button', { name: '新建目标组', exact: true })).toBeDisabled();
    await expect(page.getByText('共享后端', { exact: true })).toHaveCount(0);
    await page.getByRole('link', { name: '站点配置', exact: true }).click();
    await expect(page.getByText('隐藏站点乙', { exact: true })).toHaveCount(0);
    await expect(page.getByTestId('edit-site-' + alpha.id)).toBeVisible();
    await expect(page.getByRole('button', { name: '新建站点' })).toBeDisabled();
    const csrf = await page.evaluate(() => sessionStorage.getItem('gatebeam.csrf'));
    const denied = await page.request.put('/targets/' + target.id, { headers: { Origin: fixture.origin, 'X-CSRF-Token': csrf! }, data: { config: target.config, expected_revision: target.revision } });
    expect(denied.status()).toBe(403);
    expect(await denied.text()).not.toContain(beta.id);
    await page.getByRole('link', { name: '发布审阅', exact: true }).click();
    await expect(page.getByRole('button', { name: '生成候选并校验' })).toBeDisabled();
    const historyFirst=await(await page.request.get('/releases?limit=100&offset=0')).json();
    expect(historyFirst.items).toEqual([]);expect(historyFirst.has_more).toBe(true);expect(historyFirst.next_offset).toBe(100);
    await expect(page.getByLabel('历史已验证来源（可选）').locator('option[value="'+historical.id+'"]')).toHaveCount(1);
    await page.getByLabel('历史已验证来源（可选）').selectOption(historical.id);
    await expect(page.getByLabel('历史已验证来源（可选）')).toHaveValue(historical.id);
    expect(await page.getByRole('main').textContent()).not.toContain(beta.id);
    const current = await (await page.request.get('/sites/' + alpha.id)).json();
    expect((await page.request.post('/releases/prepare', { headers: { Origin: fixture.origin, 'X-CSRF-Token': csrf! }, data: { site_ids: [alpha.id], expected: { ['site:' + alpha.id]: current.revision, ['target:' + target.id]: 1 } } })).status()).toBe(403);
    await page.evaluate(() => sessionStorage.removeItem('gatebeam.csrf'));
    await page.getByRole('button', { name: '退出登录' }).click();
    await expect(page.getByRole('alert')).toContainText('缺少安全校验资料');
    expect((await page.request.get('/auth/session')).status()).toBe(200);
});
