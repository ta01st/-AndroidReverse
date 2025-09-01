// ==== 配置 ====
const DUMP_SO_PATH = "/data/local/tmp/libsmalldump.so"; // 你的 helper so 绝对路径
const TARGET_SO    = "libcheckqdbi.so";                 // 目标 so（子串匹配）
const INVOKE_NAME  = "Small_dump_so";                   // void Small_dump_so(char* name)
const DELAY_MS     = 1500;                              // 找不到 JNI_OnLoad 时的兜底延迟

// ==== 运行状态 ====
let loadedHelper = false;
let resolvedInvoke = null;
let pendingTarget = null;
let invokedOnce = false;

// ==== 小工具 ====
function safeStr(p) { return p && !p.isNull() ? (p.readUtf8String() || "") : ""; }
function basename(p) { const s = (p || ""); const i = s.lastIndexOf("/"); return i >= 0 ? s.slice(i+1) : s; }

function findAndroidDlopenExt() {
  return Module.findExportByName(null, "android_dlopen_ext")
      || Module.findExportByName("libdl.so", "android_dlopen_ext")
      || Module.findExportByName("libc.so", "android_dlopen_ext");
}

function resolveInvokeSymbol(helperMod) {
  // 优先按模块名找，失败再全局找
  resolvedInvoke = Module.findExportByName(helperMod.name, INVOKE_NAME) ||
                   Module.findExportByName(null,       INVOKE_NAME);
  if (!resolvedInvoke) console.log("[!] cannot resolve symbol:", INVOKE_NAME);
}

// ==== 延迟触发：优先等 JNI_OnLoad；找不到则定时 ====
function scheduleInvoke(targetPathOrName) {
  if (invokedOnce || !resolvedInvoke) return;

  const modName = basename(targetPathOrName) || TARGET_SO;
  let jni = Module.findExportByName(modName, "JNI_OnLoad");
  if (!jni) {
    // 兼容未导出符号的情况（全局匹配后过滤模块）
    const cands = DebugSymbol.findFunctionsMatching("*!JNI_OnLoad");
    for (const addr of cands) {
      const m = Process.findModuleByAddress(addr);
      if (m && m.name === modName) { jni = addr; break; }
    }
  }

  if (jni) {
    Interceptor.attach(jni, {
      onLeave() {
        if (invokedOnce) return;
        invokedOnce = true;
        new NativeFunction(resolvedInvoke, 'void', ['pointer'])(Memory.allocUtf8String(TARGET_SO));
        console.log("[+] invoked after JNI_OnLoad");
      }
    });
    console.log("[*] waiting JNI_OnLoad to finish ...");
  } else {
    console.log(`[i] JNI_OnLoad not found, fallback delay ${DELAY_MS}ms`);
    setTimeout(() => {
      if (invokedOnce || !resolvedInvoke) return;
      invokedOnce = true;
      new NativeFunction(resolvedInvoke, 'void', ['pointer'])(Memory.allocUtf8String(TARGET_SO));
      console.log("[+] invoked after delay");
    }, DELAY_MS);
  }
}

// ==== 主逻辑：hook android_dlopen_ext ====
const android_dlopen_ext = findAndroidDlopenExt();
if (!android_dlopen_ext) {
  console.log("[!] android_dlopen_ext not found");
} else {
  Interceptor.attach(android_dlopen_ext, {
    onEnter(args) {
      const path = safeStr(args[0]);
      if (path.indexOf(TARGET_SO) !== -1) pendingTarget = path;
    },
    onLeave() {
      if (!pendingTarget || loadedHelper) { pendingTarget = null; return; }

      try {
        const mod = Module.load(DUMP_SO_PATH); // 加载你的 helper so
        loadedHelper = true;
        resolveInvokeSymbol(mod);
        if (resolvedInvoke) scheduleInvoke(pendingTarget);
      } catch (e) {
        console.log("[!] load helper failed:", e);
      } finally {
        pendingTarget = null;
      }
    }
  });
  console.log("[*] hook ready");
}
