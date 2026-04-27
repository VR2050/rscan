package c1;

import android.view.KeyEvent;
import android.view.View;
import com.facebook.react.bridge.WritableNativeMap;
import d1.AbstractC0508d;
import java.util.Map;

/* JADX INFO: renamed from: c1.u, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
class C0348u {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static final Map f5667c = AbstractC0508d.a().b(23, "select").b(66, "select").b(62, "select").b(85, "playPause").b(89, "rewind").b(90, "fastForward").b(86, "stop").b(87, "next").b(88, "previous").b(19, "up").b(22, "right").b(20, "down").b(21, "left").b(165, "info").b(82, "menu").a();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private int f5668a = -1;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final W f5669b;

    C0348u(W w3) {
        this.f5669b = w3;
    }

    private void b(String str, int i3) {
        c(str, i3, -1);
    }

    private void c(String str, int i3, int i4) {
        WritableNativeMap writableNativeMap = new WritableNativeMap();
        writableNativeMap.putString("eventType", str);
        writableNativeMap.putInt("eventKeyAction", i4);
        if (i3 != -1) {
            writableNativeMap.putInt("tag", i3);
        }
        this.f5669b.r("onHWKeyEvent", writableNativeMap);
    }

    public void a() {
        int i3 = this.f5668a;
        if (i3 != -1) {
            b("blur", i3);
        }
        this.f5668a = -1;
    }

    public void d(KeyEvent keyEvent) {
        int keyCode = keyEvent.getKeyCode();
        int action = keyEvent.getAction();
        if (action == 1 || action == 0) {
            Map map = f5667c;
            if (map.containsKey(Integer.valueOf(keyCode))) {
                c((String) map.get(Integer.valueOf(keyCode)), this.f5668a, action);
            }
        }
    }

    public void e(View view) {
        if (this.f5668a == view.getId()) {
            return;
        }
        int i3 = this.f5668a;
        if (i3 != -1) {
            b("blur", i3);
        }
        this.f5668a = view.getId();
        b("focus", view.getId());
    }
}
