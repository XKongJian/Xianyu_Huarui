use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        let app_dir = std::env::var("APPDIR").unwrap_or("".to_string());
        let mut so_path = "/usr/lib/rustdesk/libsciter-gtk.so".to_owned();
        for (prefix, dir) in [
            ("", "/usr"),
            ("", "/app"),
            (&app_dir, "/usr"),
            (&app_dir, "/app"),
        ]
        .iter()
        {
            let path = format!("{prefix}{dir}/lib/rustdesk/libsciter-gtk.so");
            if std::path::Path::new(&path).exists() {
                so_path = path;
                break;
            }
        }
        sciter::set_library(&so_path).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    #[cfg(windows)]
    crate::platform::try_set_window_foreground(frame.get_hwnd() as _);
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        crate::using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String, test_with_proxy: bool) -> String {
        test_if_valid_server(host, test_with_proxy)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn http_request(&self, url: String, method: String, body: Option<String>, header: String) {
        http_request(url, method, body, header)
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn get_http_status(&self, url: String) -> Option<String> {
        get_async_http_status(url)
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn has_vram(&self) -> bool {
        has_vram()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn video_save_directory(&self, root: bool) -> String {
        video_save_directory(root)
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(&id).to_owned()
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }

    fn has_valid_2fa(&self) -> bool {
        has_valid_2fa()
    }

    fn generate2fa(&self) -> String {
        generate2fa()
    }

    pub fn verify2fa(&self, code: String) -> bool {
        verify2fa(code)
    }

    fn generate_2fa_img_src(&self, data: String) -> String {
        let v = qrcode_generator::to_png_to_vec(data, qrcode_generator::QrCodeEcc::Low, 128)
            .unwrap_or_default();
        let s = hbb_common::sodiumoxide::base64::encode(
            v,
            hbb_common::sodiumoxide::base64::Variant::Original,
        );
        format!("data:image/png;base64,{s}")
    }

    pub fn check_hwcodec(&self) {
        check_hwcodec()
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String, bool);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn has_vram();
        fn get_langs();
        fn video_save_directory(bool);
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
        fn has_valid_2fa();
        fn generate2fa();
        fn generate_2fa_img_src(String);
        fn verify2fa(String);
        fn check_hwcodec();
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAABhGlDQ1BJQ0MgcHJvZmlsZQAAeJx9kT1Iw0AYht+mSkUqHewg4pChOlkQFXHUVihChVArtOpgcukfNGlIUlwcBdeCgz+LVQcXZ10dXAVB8AfE1cVJ0UVK/C4ptIjxjuMe3vvel7vvAKFZZZrVMwFoum1mUgkxl18VQ68QEEKYZkRmljEvSWn4jq97BPh+F+dZ/nV/jgG1YDEgIBLPMcO0iTeIZzZtg/M+cZSVZZX4nHjcpAsSP3Jd8fiNc8llgWdGzWwmSRwlFktdrHQxK5sa8TRxTNV0yhdyHquctzhr1Tpr35O/MFzQV5a5TmsEKSxiCRJEKKijgipsxGnXSbGQofOEj3/Y9UvkUshVASPHAmrQILt+8D/43VurODXpJYUTQO+L43yMAqFdoNVwnO9jx2mdAMFn4Erv+GtNYPaT9EZHix0BkW3g4rqjKXvA5Q4w9GTIpuxKQVpCsQi8n9E35YHBW6B/zetb+xynD0CWepW+AQ4OgbESZa/7vLuvu2//1rT79wPpl3Jwc6WkiQAAE5pJREFUeAHtXQt0VNW5/s5kkskkEyCEZwgQSIAEg6CgYBGKiFolwQDRlWW5BatiqiIWiYV6l4uq10fN9fq4rahYwAILXNAlGlAUgV5oSXiqDRggQIBAgJAEwmQeycycu//JDAwQyJzHPpPTmW+tk8yc2fucs//v23v/+3mMiCCsYQz1A0QQWkQEEOaICCDMERFAmCMigDBHRABhjogAwhwRAYQ5IgIIc0QEEOaICCDMobkAhg8f3m/cuHHjR40adXtGRkZmampqX4vFksR+MrPDoPXzhAgedtitVmttVVXVibKysn0lJSU7tm3btrm0tPSIlg+iiQDS0tK6FBQUzMjPz/+PlJSUIeyUoMV92zFI6PFM+PEsE/Rhx+i8vLyZ7JzIBFG2cuXKZQsXLlx8+PDhGt4PwlUAjPjuRUVFL2ZnZz9uNBrNPO/1bwKBMsjcuXPfZMeCzz///BP2/1UmhDO8bshFACaTybBgwYJZ7OFfZsR34HGPMIA5Nzf3GZZ5fsUy0UvMnu87nU6P2jdRXQCDBg3quXr16hVZWVnj1L52OIIy0Lx5895hQshl1cQjBw4cqFb1+mpe7L777hvOyP+C1W3Jal43AoAy1C4GJoJJGzZs2K3WdVUTwNSpU8cw56U4UuTzA2Ws4uLiTcyZzl6zZs1WNa6pigAo50fI1wZkY7I1qxLGq1ESKBaAr87/IkK+diBbk81HMCj1CRQJgLx9cvj0Uue7RRFnmSNd3+xBg0tEk0f0no82CLAYBSRGG9A9xuD93t5BNifbMw3craR1oEgA1NRrj96+yIiuaHRje10z9l5oRlmDCxU2N6ocLriIcy+/Yst/P9dCy3eBHT1MBgyIN2KwxYhhCdEY1SkGWZZoRAntSxhke+Jg/vz578q9hmwBUCcPtfPlxlcbF1mu/vpME76sdmLj2SZUOzw+glty+RVke78LpJTLv4nePyQLb9xqZxP+r9556ffEaAHjk2IxsUssctjRJSZKq6TdEMTBokWLVsrtLJItAOrhC3W972EEfnu6GUsqHVh7ygG7vyD05WYvm95sLbbyGdcVQWtx65tFrDljZ4cNRgNwLxPDjJ7xyO1qDmmVQRwQF5MnT35WVnw5kahvn7p35cRVA42sHF98xIF3Dtpw2OoJKMbRJpFKROAP72K+w/pzDqyvdaAnqy5+08uCp1Ms6BwdmlKBuGCcvMxKgXNS48oSQEFBwa9D0bfvcIv480EH3txvY86ceLl4J0giUrkI/OGrmf/10pEG/PH4RTzb24LCPh3QyajtoCZxwTh5tLCw8C3JceXcMD8//5dy4skFOXWrjzfhhT02VDLn7nJdroRI9URAP1lZqfRaZQM+PGXFK/064slkCwwaOo2Mk2maCGDkyJH9fEO6muCY1Y0nSxqx4VSzj3hpxGgpAgpf2+TBUwfr8c8LTnyamcSCaCMC4oS4KS0tPSolnmQB0GQOaDCeT2ZdesiJ2TttaGgOLOohixgtRUA/LmPO4rQe8bivs2Y1pUDcMAF8IiWSZAGMGDHidqlxpKKREV7wTxuWHbncDFOLGC1F8E2dQ0sBEDe3sX98BZCRkTFYahwpOMa8+ge/teKHOneLYTkQo5UIojSe+CSHG8kCSE1N7SM1TrDYe86FBzY04rTdoxKpwYQHt3tNTIpVxzBBguZXSo0jWQC+CZyqY9tpFyZ+3eir79XM2W2F53Mv6hf4eaK2ApDDjZxmoOqV2ncnXZjEyLe5fIblSEzr4dW91xOM/PcGdVLTRMFCMjdyBKBqL0fJGRce/IrIB+c6vq3w6tzriV7xWJjZSdM+gABI5iakC0MqLniQs97OvP6AkzoWwRO9GfmDQ0a+LIRMAA1NInLW2XDO7qvz/d263q/6E8HMPnH4QGfkE0IiAOrafXSjA+V1/iFbXGt4HYlgJsv5H9zUUXfkE0IigA/KmvG3w662SVOJVBqkG5FkxPDORmR2jELfeAO6mgyIMwreYDa36O3CPW7z4IDVhT3nm7Gjvtl7vq17eXN+lj7JJ2gugEPnPSjc2hR8zpUpAjNL2eQ+MXiorwkTekTDEi2NICcjf2ttE9accuKzk3bUNQVUVb57FaTG409DOsgin0rB4loHNtU7QI+W08WMMZ20bTYSNBUAJXrmRids5PRdIhCqiqCbWcCcwWY8MdCEzib5DRZTlIAJ3Uze4+0hCVhVZcefjtrwk9WN9PgoPJcWh+m9zbIGe5weEY+U1eJvNXZfmkS8deIi5vROwH+nJ8p+ZjnQVAB//cmFLVVu3zeJdXgbv8cywl64ORaFWbGSc3tbMLNrz+gb5z2UgsjP+6EWxefs1/g/bzMRjOloQm5X5fcJFpoJwNosYv62Zh+ZkOfIXef3O7pHYcnYeAzs2D7m6V0PNKFlKiOfZhNdLy3PV5zH/UlmmDSaZqaZAN7b04xT1gD2VRLB80Ni8fptse1+KjeRP+X7WnxF5PvRSlqP2F1YeNKK2aw60AKaCIDa/EU7XQG5X7kIWKmMD8fG4rFBJi2SoAhE/uQ9tfj6nBPBjHC+cawBM5PjWdXDf2qZJgL46AcX6gOEr1QERP6K8WY8nBajxeMrgp3I312HDV7yEVRaTzs9WFzdiKdS+JcC3AXgZk7P+7tdrRbfckXw0Vj9kP/grjp8S+RLrPreOWFFQS/+8wq5C2DdEQ+ONwScUCiCwmEm/Dqj/ZNPxf6kHXXY6M/5EtN6yObCxjqnd/0BT3AXwJJ/tZb75YlgdM8ovDay/df5hJcPWrGxpkmR4JewakDXAjjvELGuwnOd3CzNMGbWtl9ytxnGdu7tE6jD66NKW/BO7XVEsLbGDqvbAwtHZ5CrAIj8JteNivTgDTP/1hikd9THLnK0LLHWGZgOyBIBTZD5mjUb87rz6xjiLAB3EPV624bpGS/g+Vvaf73vB/UcDk4wYv9Fl7TmbSt2+lKvAvAu3DzqS4lCETx/azTiVO7e5Y1Z/ePwm+/J+5XYx3FV+G+ZAKhK4bXAhJsAys+JONeIAA8YkCOCeJbxH78pmtdjcsO03rF4oewiLvo3JJApAlp7WGF3YUAcHxtwE0DJSX/ul9LMu9YwU9ON6GjSV+4nWIwGTEmOxdLjdskdXVeH336+SX8C2Hval1jJbf0rDfPwgPY9wHMjTOlpwtJjdskdXVeH39vQjF9x2oSHmwD2nQ1MKGSJIJZxP76PfgUwvlsMjLSfgBhsutGqncqsLm7PyE0Ah2p92V92r5+A23sYYDbqr/j3g6qBYR2N2FVPBMoXwaFGnQmAdtCovggo7f8f3l0f7f4b4ZZO0S0CUDD4VWV3e3c447FJFRcBnG2kQaCAEzJFkJmkfwEMshhl+kKXw9McqpomD3qY1K8OuQigjqa6icravxS+bwf9Fv9+9DYbrkqrPBHUNetIAFanKClx1zNGV7P+BZAU4yvFFIqgpT9BfXARQJN/3qdCEXBq+moKasm0XgVIE4F/V1O1wakVIAQk2vddhgj0n/8pmcINmsPBi4AP/ZwE4N1EU4WlXLZm6B5Wf1ewwmVoMXoaC0jwD9wpFEHLwlF9o8bpCaI53LadLJz6Q7gIIJG2KVDY9KHPJy7oXwCVVneQgr+xnWgncx7gIoBuFoAm7ngUiqC8Vv8C2H/B5xErEAFR3z1GRwKgaVsprA1//Lz0zp/A8Lur9S+AnbW+XkAFS9OTYw3cpsJxGwtI7wwmAGnt/qsNU3pSZE1K5gBF6bM9cKLRjcMXL21hLlsE6fH8Jm5xu3JWdwGbDouSO38Cw1ubgH+cEHFXqj4FsO6kkrWQlz/flKBDAQzrGZg4+SJYU+5mAtDnmMCqSqfCllDLZxpR5AVuV77Dv52kxM6fq8Ov3OdB0QQRsTobFj7U4Mbfz/iGcRWK4I7O/CbEchPAoK4CulsEnLFK6/y52jC1jSJWMRFMH6qviSHv/uSASNW/AEUtoSSTgMwEfmnnJgBKz4R0YPleKWr3nbwq/J936UsAVY0efHLQtx5Q4VrIu7uauK4P5LouICdTwPI9Pi9IgQjKzuqrOfife+xweDe+hCL/h37K7sl3KRxXAdw/CKzuRosxFIigfyf91P9bqpvxaUVTyxeF/g91/mX35LsghqsAOsQKmDQY+OxHMegirzXDzB6pj1bA+SYRj261+ZKkvOp7oEcMEjn1APrBfXXwjBFMAD9ApgcMFNwWhcduaf8CoJVQM/5uQ2XDVZtfKhDB9FT+28ZxF8C9AwX07wwcqZPuAT/Fcv7/TjRwWxalJn5X6sDayubW0yJDBL3MBuQk818PyV0AtLJ59p3sWCvN+Xmakf++Tsh/ebcDRT86L59QQQSzBmizFF6TPYIeGwm8+h1QYw1OBLPuEPCuDsinYr9wuwNv/+jbCKItkoMUQcdoAU+ma7NrqCYCiI8R8LtxIuYWo816b/ZoA/7HS74WTyYf9U4R07+z48tjzdKqtiB2RZ+TYUYnzs6fH5rtE/jUaOD9bcCx87iuCJ4bLeBtHZC/8YQLj2224ziHfQ97xBrw2wzt3jSmmQBoi5e3ckQ8/ClaNcScMQKKFJBPxTGNHiaw0oaXgI4xD//3251YcShgqZeMzp0bieDVYXFI0HAvBE33Cs67WcC88SLe3OyzjUhkiXjxbgEv3yuPOIdLxB+2uPHhHo93L8L+icAztxswY2gUEmPVMeT+Wg/e+b4JS8td3vkJavTwtSaC0V2j8GiatptgaSoAssHrEwXk3yLim4Mtaf9FhoCsHvKIsjWLmLTCje+O+iZdsMscqWelyQY3XtzsRs5AA6YMMmBCfwOSJCwyIZ4qznuw/qgbqw66sP20+9L1LxMMVUVA6wc+/pm27xsmhOSFEUOTBXYouwaRn7PcjU1HxFY9cHuTiM/2efDZfo/358FdgVuY0AYlGZCSICApDt53ChAfVubH1dhFbxG/v1bEzjMenGz1tfS+LxzeVPL6rXHel1lojZC+NEoubPS+oeUeH/lo09D0d99ZdtQQqZdLi0se+TWfA26mRvHe1oBPSgyezQzN/oe6E4CX/GU+8pV64FeE55Oz2wqf3sGAT8fGheyVM7oSgJf8v3p8cw3BgRhtRZBoMuCLeyze/6GCbgTQyMiftJRyPjgTo40IzKy6//yeeGR2Cu1EFzkCoEpUU8kS+TlLRGw+EnBSxyKgae6rJ8RhbE/V85+n7SBXQs4T0PYP8TLiyQJtN5O7lJFfgVa9fb2JgFoeq++NwwN9uKx9t0uNIFkAVqu11mKxaCaAFXuAjQfBzQPXUgSJMQLW3h+HMcl8al7iRmocyU9SWVl5PCsrq0/bIdXBxkPg5oEHF16dew3oyBy+iWZkJPKr8xk3x6TGkSyA8vLy/UwAd0qNJxdGv7ehYxHk9DNi6T1m5u0LqtmlNRA3UuNIFsCuXbt25OXlzZQaTy5yBgOLd4ADqVLDS49rZtX86z+LwbNDozWZ21BSUrJDahzJAtiyZcsmtCSRf4oYcrMETB8hYuku6EoEdyYb8PGEWFbka9ZgErdt27ZJaiTJAigtLT1aVVX1r5SUlJulxpUDsvHifAETBoqYtw44STuwt2MR9Igz4LU7ozF9sFHT3j3ihHFTKTWeLHd05cqVy+bOnftHOXHlgOw4bbiAKUNEvLcNeGsLUGdrXyLoZALmjDDit7dGwxKjHfF+ECdy4skSwMKFCxc/99xzfzAajdpNXWGIi6H5BMDTo0V8XAK89w8Bx+pDK4LeCQJm3WrEzKGh29be5XLZiBM5cWUJ4PDhw+eKi4sX5ebmzpITXykSmKHn/ByYPUbEV+UCFjP/YF25CKfCFUjBho8xinggzYAZQ4yYmMZv945gwbj4hDiRE1d2jwSrAv4rOzt7OisFOsi9hlJEMcNns1YCHQ0OZohyYP1PIr6pEFDTqK4I6IXe4/sJyEmPwgPpBtVmGykFy/0NxIXc+LIFwBR3pqio6KV58+a9I/caaoKWoT0yDOwQvNyV14goOQ58Xy16F5dW1ArMgRTh9rdfrrchE/vXqwNtcWPATd0E7ySSkb0EZHYRQjZkeyMQB8SF3PiK+iQXLFjwPisFcrOyssYpuY7aIJ4yGXmZ3bzfLp2ncYWzVnjnDl50tmxpS3MSaREmVSu0vV23eIS8SA8WZWVlW4gDJddQJACn0+nJy8t7ZBeDxWLh9FIT9UDEJrPcnXxFpaUPsq+G1Wo9RbYnDpRcR/GoxIEDB6rZg+QwR2RzKP2BcALV+8zmk8j2Sq+lyrDUhg0b9uTn52eztmhxRAR8QeSTrZnNd6txPdXGJdesWbOV+QN3rV69+ks9VAd6hK/Yn6QW+QRVB6apJBjBwESwnDmGd6l57XAHOXxU56tR7AdC9ZkJ9IBMAxOYd/oMa5++EqkSlIGKfGrqkbev1OFrDVymptCDzp8//71FixateuONN36fm5v7OBMCvzcg/xuCEW+n3lbq5FHSzm8LXGcF04M/9NBDs9PS0l4pKCiYwZyXab5RRH22vfhDrKqqKqOBHerbZ/ar4X1DTaaFUz91YWFhER3Dhw9PHTdu3PhRo0bdnpGRMTg1NbUvcxqTWDAaWGr/mwGpAyrK7TSHj6bYlZeX7yspKdlJ4/k03K7lg2i+LmD37t2V7PgL+/gXre8dwbXQzcKQCPggIoAwR0QAYY6IAMIcEQGEOSICCHNEBBDmiAggzBERQJgjIoAwR0QAYY7/B1LDyJ6QBLUVAAAAAElFTkSuQmCC".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,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".into()
    }
}
