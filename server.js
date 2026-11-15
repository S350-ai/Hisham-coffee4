// Hisham Coffee – zero-dependency Node server (Node >= 22.13). Data lives in ./data (SQLite + uploads).
const http=require("http"),fs=require("fs"),path=require("path"),crypto=require("crypto"),{DatabaseSync}=require("node:sqlite");
const PORT=process.env.PORT||3000,DIR=process.env.DATA_DIR||path.join(__dirname,"data");
const AP=process.env.ADMIN_PATH||"/hisham-admin"; // secret admin address, never linked from the public site
fs.mkdirSync(DIR+"/uploads",{recursive:true});
const db=new DatabaseSync(DIR+"/hisham.db");
db.exec("create table if not exists docs(col text,id text,data text,primary key(col,id));create table if not exists cfg(k text primary key,v text)");
const list=c=>db.prepare("select id,data from docs where col=?").all(c).map(r=>({id:r.id,...JSON.parse(r.data)}));
const get=(c,i)=>{const r=db.prepare("select data from docs where col=? and id=?").get(c,i);return r?{id:i,...JSON.parse(r.data)}:null};
const put=(c,i,o)=>{const{id,...d}=o;db.prepare("insert or replace into docs values(?,?,?)").run(c,i,JSON.stringify(d))};
const hash=(pw,salt=crypto.randomBytes(16).toString("hex"))=>salt+":"+crypto.scryptSync(pw,salt,32).toString("hex");
const check=(pw,h)=>{const[s,x]=h.split(":");const y=hash(pw,s).split(":")[1];return crypto.timingSafeEqual(Buffer.from(x),Buffer.from(y))};
if(!db.prepare("select v from cfg where k='pw'").get())db.prepare("insert into cfg values('pw',?)").run(hash(process.env.ADMIN_PASSWORD||"112212"));
if(!list("products").length)JSON.parse(fs.readFileSync(path.join(__dirname,"seed.json"))).forEach((p,k)=>put("products",p.id,p));
const build=b=>{const s=x=>String(x||"").trim(),name=s(b.name).slice(0,100),bld=s(b.bld).slice(0,100),room=s(b.room).slice(0,100),note=s(b.note).slice(0,1000);
 if(!name||!bld||!room||!Array.isArray(b.items)||!b.items.length||b.items.length>50)return{e:"invalid"};
 let total=0;const items=[];for(const it of b.items){const pr=get("products",String(it.id)),q=Math.floor(+it.q),i=Math.floor(+it.i||0);if(!pr||!pr.on||!(q>=1&&q<=50)||pr.pr[i]===undefined)return{e:"invalid item"};items.push({id:pr.id,i,n:pr.n,l:pr.pr.length>1?(pr.lb||"s,l").split(",")[i]:"",q,p:pr.pr[i]});total+=pr.pr[i]*q}
 return{name,bld,room,note,items,total}};
const sess=new Map(),tries=new Map();
const cookie=r=>Object.fromEntries((r.headers.cookie||"").split(";").map(x=>x.trim().split("=")).filter(x=>x[0]));
const isAdmin=r=>{const t=cookie(r).sid,e=sess.get(t);return !!(e&&e>Date.now())};
const J=(res,code,o,h={})=>{res.writeHead(code,{"Content-Type":"application/json","Cache-Control":"no-store",...h});res.end(JSON.stringify(o))};
const body=(r,max=6e6)=>new Promise((ok,no)=>{const a=[];let n=0;r.on("data",c=>{n+=c.length;if(n>max){no(new Error("big"));r.destroy()}else a.push(c)});r.on("end",()=>ok(Buffer.concat(a)));r.on("error",no)});
const MIME={png:"image/png",jpg:"image/jpeg",jpeg:"image/jpeg",webp:"image/webp",gif:"image/gif"};
http.createServer(async(req,res)=>{
 const u=new URL(req.url,"http://x"),p=u.pathname,m=req.method;
 res.setHeader("X-Content-Type-Options","nosniff");res.setHeader("X-Frame-Options","DENY");res.setHeader("Referrer-Policy","same-origin");
 try{
 if(m=="GET"&&(p=="/"||p==AP)){let h=fs.readFileSync(path.join(__dirname,"public/index.html"),"utf8");if(p==AP)h=h.replace("</head>","<script>window.IS_ADMIN_PAGE=true</script></head>");res.writeHead(200,{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"});return res.end(h)}
 if(m=="GET"&&p=="/logo.png"){res.writeHead(200,{"Content-Type":"image/png","Cache-Control":"public,max-age=3600"});return res.end(fs.readFileSync(path.join(__dirname,"public/logo.png")))}
 if(m=="GET"&&p.startsWith("/uploads/")){const f=path.join(DIR,"uploads",path.basename(p)),e=path.extname(f).slice(1);if(!MIME[e]||!fs.existsSync(f))return J(res,404,{e:"nf"});res.writeHead(200,{"Content-Type":MIME[e],"Cache-Control":"public,max-age=86400"});return res.end(fs.readFileSync(f))}
 if(!p.startsWith("/api/"))return J(res,404,{e:"nf"});
 const[,,col,id]=p.split("/"),adm=isAdmin(req);
 if(col=="login"&&m=="POST"){const ip=(req.headers["x-forwarded-for"]||req.socket.remoteAddress||"").split(",")[0],t=tries.get(ip)||{n:0,t:Date.now()};if(Date.now()-t.t>6e5){t.n=0;t.t=Date.now()}if(t.n>=5)return J(res,429,{e:"too many attempts, wait 10 minutes"});
  const b=JSON.parse(await body(req,1e4));if(!check(String(b.password||""),db.prepare("select v from cfg where k='pw'").get().v)){t.n++;tries.set(ip,t);return J(res,401,{e:"wrong password"})}
  tries.delete(ip);const sid=crypto.randomBytes(32).toString("hex");sess.set(sid,Date.now()+12*36e5);const sec=req.headers["x-forwarded-proto"]=="https"?"; Secure":"";return J(res,200,{ok:1},{"Set-Cookie":`sid=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200${sec}`})}
 if(col=="logout"&&m=="POST"){sess.delete(cookie(req).sid);return J(res,200,{ok:1},{"Set-Cookie":"sid=; Path=/; Max-Age=0"})}
 if(col=="me")return adm?J(res,200,{ok:1}):J(res,401,{e:"auth"});
 if(col=="order"||col=="track"){
  const b=JSON.parse(await body(req,2e5)),sh=x=>crypto.createHash("sha256").update(String(x)).digest("hex"),pub=o=>{const{tk,...r}=o;return r};
  if(col=="track")return J(res,200,(Array.isArray(b)?b:[]).slice(0,30).map(x=>{const o=get("orders",String(x.num));return o&&o.tk==sh(x.token)?pub(o):null}).filter(Boolean));
  if(m=="POST"&&!id){const v=build(b);if(v.e)return J(res,400,v);let num;for(let k=0;k<200;k++){const c=10000+crypto.randomInt(90000);if(!get("orders",String(c))&&!get("nums",String(c))){num=c;break}}if(!num)return J(res,500,{e:"no number"});
   const token=crypto.randomBytes(16).toString("hex");put("nums",String(num),{});put("orders",String(num),{num,...v,st:"new",ts:Date.now(),tk:sh(token)});return J(res,200,{num,token})}
  const o=id&&get("orders",id);if(!o||o.tk!=sh(b.token)||o.st!="new")return J(res,403,{e:"locked"});
  if(m=="PUT"){const v=build(b);if(v.e)return J(res,400,v);put("orders",id,{...o,...v,edited:Date.now()});return J(res,200,{ok:1})}
  if(m=="PATCH"){o.st="cancelled";put("orders",id,o);return J(res,200,{ok:1})}}
 if(m=="GET"&&(col=="products"||col=="site")){if(id){return J(res,200,get(col,id)||{})}return J(res,200,list(col))}
 if(!adm)return J(res,401,{e:"auth"});
 if(col=="orders"&&m=="GET")return J(res,200,list("orders").map(({tk,...r})=>r));
 if(col=="orders"&&m=="DELETE"){const del=i=>db.prepare("delete from docs where col='orders' and id=?").run(i);
  if(id)del(id);else if(u.searchParams.get("done"))list("orders").filter(o=>["delivered","rejected","cancelled"].includes(o.st)).forEach(o=>del(o.id));else return J(res,400,{e:"invalid"});return J(res,200,{ok:1})}
 if(col=="orders"&&m=="PATCH"){const o=get("orders",id),b=JSON.parse(await body(req,1e4));if(!o||!["new","preparing","ready","delivered","rejected","cancelled"].includes(b.st))return J(res,400,{e:"invalid"});o.st=b.st;put("orders",id,o);return J(res,200,{ok:1})}
 if((col=="products"||col=="site")&&m=="PUT"){const b=JSON.parse(await body(req,2e5));put(col,id,b);return J(res,200,{ok:1})}
 if(col=="products"&&m=="DELETE"){db.prepare("delete from docs where col='products' and id=?").run(id);return J(res,200,{ok:1})}
 if(col=="upload"&&m=="POST"){const t=String(req.headers["content-type"]||""),e=Object.keys(MIME).find(k=>MIME[k]==t&&k!="jpg");if(!e)return J(res,400,{e:"image only"});const f=crypto.randomBytes(12).toString("hex")+"."+e;fs.writeFileSync(path.join(DIR,"uploads",f),await body(req));return J(res,200,{url:"/uploads/"+f})}
 if(col=="password"&&m=="POST"){const b=JSON.parse(await body(req,1e4));if(!check(String(b.old||""),db.prepare("select v from cfg where k='pw'").get().v))return J(res,403,{e:"wrong current password"});if(String(b.new||"").length<6)return J(res,400,{e:"min 6 chars"});db.prepare("update cfg set v=? where k='pw'").run(hash(String(b.new)));sess.clear();return J(res,200,{ok:1})}
 J(res,404,{e:"nf"})}catch(e){J(res,500,{e:"error"})}
}).listen(PORT,()=>console.log(`Hisham Coffee on :${PORT} — admin at ${AP}`));
