// Run with jsdom installed: node server/tests/ui_dom_test.cjs
const { JSDOM } = require("jsdom");
const fs = require("node:fs");
const path = require("node:path");
const assert = require("node:assert/strict");
const staticDir = path.join(__dirname, "../app/static");
const dom = new JSDOM(fs.readFileSync(path.join(staticDir, "index.html"), "utf8"),
  {url:"http://localhost/", runScripts:"outside-only"});
const w = dom.window, writes = [], urls = [];
const device = {id:"one", hostname:"test-debian", os_name:"Debian GNU/Linux",
  package_manager:"apt", platform:"linux", online:true, inventory:{}, agent_settings:{},
  vulnerability_severity_counts:{}, agent_version:"0.12.0"};
let interval = 0;
w.sessionStorage.setItem("fleetviewAdminToken","retired-token");
w.HTMLDialogElement.prototype.showModal = function() {};
w.HTMLDialogElement.prototype.close = function() {};
w.confirm = () => false;
w.fetch = async (url, options={}) => {
  urls.push(url);
  let data = [];
  if(options.body) writes.push(JSON.parse(options.body));
  if(url.endsWith("/auth/status")) data={setup_required:false};
  else if(url.endsWith("/auth/me")) data={user:{id:"owner",username:"owner",role:"admin",must_change_password:false},csrf_token:"csrf"};
  else if(url.endsWith("/devices/one")) data=device;
  else if(url.endsWith("/devices")) data=[device];
  else if(url.endsWith("/packages")) data=[{id:"pkg",name:"htop",apt_name:"htop",pacman_name:"",winget_id:""}];
  else if(url.endsWith("/settings")) data={default_metrics_interval_seconds:60,default_inventory_interval_seconds:900};
  else if(url.endsWith("/vulnerability-schedule")) {
    if(options.body) interval=JSON.parse(options.body).interval_hours;
    data={interval_hours:interval,supported:true,next_run_at:null};
  } else if(url.includes("/reports/history")) {
    data=["2026-01-01","2026-03-01"].map(date=>({date,device_count:1,fully_patched_percent:50,
      no_critical_high_percent:100,online_percent:100,total_vulnerabilities:2}));
  }
  return {ok:true,status:200,json:async()=>data};
};
const tick=()=>new Promise(resolve=>setTimeout(resolve,20));
const el=id=>w.document.querySelector(id);
const submit=id=>el(id).dispatchEvent(new w.Event("submit",{bubbles:true,cancelable:true}));
(async()=>{
  w.eval(fs.readFileSync(path.join(staticDir,"app.js"),"utf8"));
  await tick();
  assert.equal(w.sessionStorage.getItem("fleetviewAdminToken"),null);
  assert.equal(el("#authButton").textContent,"Sign out");
  for(const name of ["Blue","Purple","Amber","Pink","Green"]) {
    const button=el(`button[aria-label="${name}"]`);
    button.click();
    assert.equal(w.document.documentElement.dataset.theme,name.toLowerCase());
    assert(w.document.documentElement.style.getPropertyValue("--bg"));
  }
  el("#trendDevice").value="one";
  el("#trendStart").value="2026-01-01";
  el("#trendEnd").value="2026-03-01";
  submit("#trendFilters");
  await tick();
  assert(urls.some(url=>url.includes("device_id=one") && url.includes("start=2026-01-01")));
  assert(el("#reportsTrends").textContent.includes("test-debian"));
  el("#scanInterval").value="24";
  submit("#scanScheduleForm");
  await tick();
  assert(writes.some(x=>x.interval_hours===24));
  const checkbox=el('[data-deploy-device="one"]');
  checkbox.checked=true;
  checkbox.dispatchEvent(new w.Event("change",{bubbles:true}));
  el('[data-uninstall-package="pkg"]').click();
  await tick();
  assert(!writes.some(x=>x.type==="UNINSTALL_PACKAGE"));
  w.confirm=()=>true;
  el('[data-uninstall-package="pkg"]').click();
  await tick();
  assert(writes.some(x=>x.type==="UNINSTALL_PACKAGE" && x.options.confirmed && x.options.package==="htop"));
  device.agent_version="0.15.0";
  device.inventory={docker_available:true,docker_containers:[{id:"abcdef012345",name:"web",image:"nginx",state:"running",status:"Up",ports:[]}]};
  w.eval('openDeviceDetails("one", "docker")');
  await tick();
  assert.equal(el('[data-docker-action="stop"]').dataset.containerId,"abcdef012345");
  assert(el('[data-docker-action="restart"]'));
  w.confirm=()=>false;
  el('[data-docker-action="stop"]').click();
  await tick();
  assert(!writes.some(x=>x.type==="DOCKER_CONTAINER_ACTION"));
  w.confirm=()=>true;
  el('[data-docker-action="stop"]').click();
  await tick();
  assert(writes.some(x=>x.type==="DOCKER_CONTAINER_ACTION" && x.options.action==="stop" && x.options.confirmed));
  console.log("PASS: DOM reports, schedules, uninstall confirmation and Docker controls");
  w.close();
})().catch(error=>{console.error(error);w.close();process.exitCode=1;});
