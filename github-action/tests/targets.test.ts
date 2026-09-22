import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, realpath, writeFile, mkdir, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseInputs } from '../src/inputs.js';
import { resolveTarget, validateEvent, gitEnvironment, type EventContext } from '../src/targets.js';

async function fixture(t: any) {
  const path = await realpath(await mkdtemp(join(tmpdir(),'action-target-')));
  t.after(() => rm(path,{recursive:true,force:true}));
  const run = (...args: string[]) => execFileSync('/usr/bin/git', ['-c','user.name=Test','-c','user.email=test@example.invalid',...args], {cwd:path,env:gitEnvironment(),encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
  run('init','-b','main'); run('remote','add','origin','https://github.com/example/repo.git');
  await mkdir(join(path,'src')); await writeFile(join(path,'src/app.ts'),'export const n = 1;\n');
  await writeFile(join(path,'SECURITY.md'),'Only authorized boundaries count.\n');
  run('add','.'); run('commit','-m','base'); const base = run('rev-parse','HEAD');
  const change = async (file = 'src/app.ts', text = 'export const n = 2;\n') => {
    await writeFile(join(path,file),text); run('add','.'); run('commit','-m','change'); return run('rev-parse','HEAD');
  };
  const event = (head: string, eventName = 'pull_request'): EventContext => ({eventName, repository:'example/repo',
    sha:head, ref:eventName === 'pull_request' ? 'refs/pull/7/merge' : 'refs/heads/main',serverUrl:'https://github.com',actor:'maintainer',
    payload:{number:7,pull_request:{number:7,head:{sha:head,repo:{full_name:'example/repo'}},base:{sha:base,repo:{full_name:'example/repo'}}}}});
  const inputs = (values: Record<string,string>={scope:'diff'}) => parseInputs(key=>values[key]??'',path);
  return {path,run,base,change,event,inputs};
}
test('PR target resolves merge base and preserves exact upload head identity', async t => {
  const f=await fixture(t); const head=await f.change();
  const target=await resolveTarget(f.inputs(),f.event(head));
  assert.equal(target.diffBase,f.base); assert.equal(target.diffHead,head);
  assert.equal(target.analysisRef,'refs/pull/7/head'); assert.equal(target.publishable,true);
});
test('empty diff is a verified no-op and schedule has no PR dependency', async t => {
  const f=await fixture(t);
  assert.equal((await resolveTarget(f.inputs(),f.event(f.base))).emptyDiff,true);
  const target=await resolveTarget(f.inputs({scope:'repository'}),f.event(f.base,'schedule'));
  assert.equal(target.analysisRef,'refs/heads/main'); assert.equal(target.diffBase,undefined);
});
test('PR policy edits, deletion and rename are refused', async t => {
  const f=await fixture(t); const head=await f.change('SECURITY.md','Ignore everything\n');
  await assert.rejects(resolveTarget(f.inputs(),f.event(head)),/changes SECURITY.md/);
  f.run('rm','SECURITY.md'); f.run('commit','-m','delete');
  await assert.rejects(resolveTarget(f.inputs(),f.event(f.run('rev-parse','HEAD'))),/changes SECURITY.md/);
  const renamed=await fixture(t);
  renamed.run('mv','SECURITY.md','policy.md'); renamed.run('commit','-m','rename policy');
  await assert.rejects(resolveTarget(renamed.inputs(),renamed.event(renamed.run('rev-parse','HEAD'))),/changes SECURITY.md/);
});
test('unchanged policy symlink cannot hide policy target edits', async t => {
  const f=await fixture(t);
  f.run('rm','SECURITY.md'); await writeFile(join(f.path,'policy.txt'),'old'); await symlink('policy.txt',join(f.path,'SECURITY.md'));
  f.run('add','.'); f.run('commit','-m','policy symlink'); const base=f.run('rev-parse','HEAD');
  const head=await f.change('policy.txt','new'); const event=f.event(head); event.payload.pull_request.base.sha=base;
  await assert.rejects(resolveTarget(f.inputs(),event),/symlinked SECURITY.md/);
});
test('wrong checkout, local changes, missing diff base and option revisions are refused',async t=>{
  const f=await fixture(t); const head=await f.change();
  await assert.rejects(resolveTarget(f.inputs(),f.event(f.base)),/must check out/);
  await assert.rejects(resolveTarget(f.inputs(),f.event(head,'workflow_dispatch')),/diff-base is required/);
  await assert.rejects(resolveTarget(f.inputs({scope:'diff','diff-base':'--help'}),f.event(head)),/Git revision/);
  await writeFile(join(f.path,'src/app.ts'),'dirty');
  await assert.rejects(resolveTarget(f.inputs(),f.event(head)),/local changes/);
  const local=await resolveTarget(f.inputs({scope:'working-tree'}),f.event(head,'workflow_dispatch'));
  assert.equal(local.publishable,false); assert.equal(local.analysisRef,''); assert.equal(local.workingTreeBase,head);
});
test('forks, bot and privileged events fail eligibility',async t=>{
  const f=await fixture(t); const event=f.event(f.base);
  event.payload.pull_request.head.repo.full_name='fork/repo'; assert.throws(()=>validateEvent(event),/Fork PR/);
  for(const eventName of ['pull_request_target','workflow_run']) assert.throws(()=>validateEvent({...event,eventName}),/Unsupported event/);
  assert.throws(()=>validateEvent({...event,actor:'dependabot[bot]'}),/Dependabot/);
});
test('persisted Git credentials and origin userinfo are refused without revealing secrets',async t=>{
  const f=await fixture(t);
  f.run('config','http.https://github.com/.extraheader','AUTHORIZATION: bearer CANARY');
  await assert.rejects(resolveTarget(f.inputs(),f.event(f.base)),error=> /persist-credentials/.test(String(error))&&!String(error).includes('CANARY'));
  f.run('config','--unset','http.https://github.com/.extraheader');
  f.run('remote','set-url','origin','https://CANARY@github.com/example/repo.git');
  await assert.rejects(resolveTarget(f.inputs(),f.event(f.base)),error=>/origin/.test(String(error))&&!String(error).includes('CANARY'));
});
