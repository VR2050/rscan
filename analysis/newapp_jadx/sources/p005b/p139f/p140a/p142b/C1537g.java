package p005b.p139f.p140a.p142b;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.util.Pair;
import android.view.MotionEvent;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.core.content.ContextCompat;
import com.alibaba.fastjson.asm.Label;
import com.blankj.utilcode.util.UtilsTransActivity;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p139f.p140a.p141a.C1530a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.f.a.b.g */
/* loaded from: classes.dex */
public final class C1537g {

    /* renamed from: a */
    public static C1537g f1734a;

    /* renamed from: b */
    public static c f1735b;

    /* renamed from: c */
    public static c f1736c;

    /* renamed from: d */
    public String[] f1737d;

    /* renamed from: e */
    public a f1738e;

    /* renamed from: f */
    public d f1739f;

    /* renamed from: g */
    public Set<String> f1740g;

    /* renamed from: h */
    public List<String> f1741h;

    /* renamed from: i */
    public List<String> f1742i;

    /* renamed from: j */
    public List<String> f1743j;

    /* renamed from: k */
    public List<String> f1744k;

    /* renamed from: b.f.a.b.g$a */
    public interface a {

        /* renamed from: b.f.a.b.g$a$a, reason: collision with other inner class name */
        public interface InterfaceC5105a {
        }

        /* renamed from: a */
        void m702a(@NonNull UtilsTransActivity utilsTransActivity, @NonNull List<String> list, @NonNull InterfaceC5105a interfaceC5105a);
    }

    @RequiresApi(api = 23)
    /* renamed from: b.f.a.b.g$b */
    public static final class b extends UtilsTransActivity.AbstractC3220a {

        /* renamed from: c */
        public static int f1745c = -1;

        /* renamed from: e */
        public static b f1746e = new b();

        /* renamed from: b.f.a.b.g$b$a */
        public class a implements a.InterfaceC5105a {
            public a(b bVar, UtilsTransActivity utilsTransActivity) {
            }
        }

        @Override // com.blankj.utilcode.util.UtilsTransActivity.AbstractC3220a
        /* renamed from: a */
        public boolean mo703a(@NonNull UtilsTransActivity utilsTransActivity, MotionEvent motionEvent) {
            utilsTransActivity.finish();
            return true;
        }

        @Override // com.blankj.utilcode.util.UtilsTransActivity.AbstractC3220a
        /* renamed from: b */
        public void mo704b(@NonNull UtilsTransActivity utilsTransActivity, int i2, int i3, Intent intent) {
            utilsTransActivity.finish();
        }

        @Override // com.blankj.utilcode.util.UtilsTransActivity.AbstractC3220a
        /* renamed from: c */
        public void mo705c(@NonNull UtilsTransActivity utilsTransActivity, @Nullable Bundle bundle) {
            utilsTransActivity.getWindow().addFlags(262160);
            int intExtra = utilsTransActivity.getIntent().getIntExtra("TYPE", -1);
            if (intExtra == 1) {
                C1537g c1537g = C1537g.f1734a;
                if (c1537g == null) {
                    utilsTransActivity.finish();
                    return;
                }
                List<String> list = c1537g.f1741h;
                if (list == null) {
                    utilsTransActivity.finish();
                    return;
                }
                if (list.size() <= 0) {
                    utilsTransActivity.finish();
                    return;
                }
                Objects.requireNonNull(C1537g.f1734a);
                C1537g c1537g2 = C1537g.f1734a;
                a aVar = c1537g2.f1738e;
                if (aVar == null) {
                    utilsTransActivity.requestPermissions((String[]) c1537g2.f1741h.toArray(new String[0]), 1);
                    return;
                } else {
                    aVar.m702a(utilsTransActivity, c1537g2.f1741h, new a(this, utilsTransActivity));
                    C1537g.f1734a.f1738e = null;
                    return;
                }
            }
            if (intExtra == 2) {
                f1745c = 2;
                Intent intent = new Intent("android.settings.action.MANAGE_WRITE_SETTINGS");
                StringBuilder m586H = C1499a.m586H("package:");
                m586H.append(C4195m.m4792Y().getPackageName());
                intent.setData(Uri.parse(m586H.toString()));
                if (C1550t.m729f(intent)) {
                    utilsTransActivity.startActivityForResult(intent, 2);
                    return;
                } else {
                    C1537g.m698d();
                    return;
                }
            }
            if (intExtra != 3) {
                utilsTransActivity.finish();
                return;
            }
            f1745c = 3;
            Intent intent2 = new Intent("android.settings.action.MANAGE_OVERLAY_PERMISSION");
            StringBuilder m586H2 = C1499a.m586H("package:");
            m586H2.append(C4195m.m4792Y().getPackageName());
            intent2.setData(Uri.parse(m586H2.toString()));
            if (C1550t.m729f(intent2)) {
                utilsTransActivity.startActivityForResult(intent2, 3);
            } else {
                C1537g.m698d();
            }
        }

        @Override // com.blankj.utilcode.util.UtilsTransActivity.AbstractC3220a
        /* renamed from: d */
        public void mo706d(@NonNull UtilsTransActivity utilsTransActivity) {
            int i2 = f1745c;
            if (i2 != -1) {
                if (i2 == 2) {
                    if (C1537g.f1735b != null) {
                        if (Settings.System.canWrite(C4195m.m4792Y())) {
                            C1537g.f1735b.m708a();
                        } else {
                            C1537g.f1735b.m709b();
                        }
                        C1537g.f1735b = null;
                    }
                } else if (i2 == 3 && C1537g.f1736c != null) {
                    if (Settings.canDrawOverlays(C4195m.m4792Y())) {
                        C1537g.f1736c.m708a();
                    } else {
                        C1537g.f1736c.m709b();
                    }
                    C1537g.f1736c = null;
                }
                f1745c = -1;
            }
        }

        @Override // com.blankj.utilcode.util.UtilsTransActivity.AbstractC3220a
        /* renamed from: e */
        public void mo707e(@NonNull UtilsTransActivity utilsTransActivity, int i2, @NonNull String[] strArr, @NonNull int[] iArr) {
            utilsTransActivity.finish();
            C1537g c1537g = C1537g.f1734a;
            if (c1537g == null || c1537g.f1741h == null) {
                return;
            }
            c1537g.m699a(utilsTransActivity);
            c1537g.m701f();
        }
    }

    /* renamed from: b.f.a.b.g$c */
    public interface c {
        /* renamed from: a */
        void m708a();

        /* renamed from: b */
        void m709b();
    }

    /* renamed from: b.f.a.b.g$d */
    public interface d {
        /* renamed from: a */
        void mo300a(boolean z, @NonNull List<String> list, @NonNull List<String> list2, @NonNull List<String> list3);
    }

    public C1537g(String... strArr) {
        this.f1737d = strArr;
        f1734a = this;
    }

    /* renamed from: b */
    public static Pair<List<String>, List<String>> m696b(String... strArr) {
        List emptyList;
        String[] strArr2;
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList();
        try {
            String[] strArr3 = C4195m.m4792Y().getPackageManager().getPackageInfo(C4195m.m4792Y().getPackageName(), 4096).requestedPermissions;
            emptyList = strArr3 == null ? Collections.emptyList() : Arrays.asList(strArr3);
        } catch (PackageManager.NameNotFoundException e2) {
            e2.printStackTrace();
            emptyList = Collections.emptyList();
        }
        for (String str : strArr) {
            if (str != null) {
                switch (str) {
                    case "LOCATION":
                        strArr2 = C1530a.f1706d;
                        break;
                    case "SENSORS":
                        strArr2 = C1530a.f1710h;
                        break;
                    case "STORAGE":
                        strArr2 = C1530a.f1712j;
                        break;
                    case "SMS":
                        strArr2 = C1530a.f1711i;
                        break;
                    case "PHONE":
                        if (Build.VERSION.SDK_INT < 26) {
                            strArr2 = C1530a.f1709g;
                            break;
                        } else {
                            strArr2 = C1530a.f1708f;
                            break;
                        }
                    case "ACTIVITY_RECOGNITION":
                        strArr2 = C1530a.f1713k;
                        break;
                    case "CONTACTS":
                        strArr2 = C1530a.f1705c;
                        break;
                    case "CALENDAR":
                        strArr2 = C1530a.f1703a;
                        break;
                    case "MICROPHONE":
                        strArr2 = C1530a.f1707e;
                        break;
                    case "CAMERA":
                        strArr2 = C1530a.f1704b;
                        break;
                    default:
                        strArr2 = new String[]{str};
                        break;
                }
            } else {
                strArr2 = new String[0];
            }
            boolean z = false;
            for (String str2 : strArr2) {
                if (emptyList.contains(str2)) {
                    arrayList.add(str2);
                    z = true;
                }
            }
            if (!z) {
                arrayList2.add(str);
            }
        }
        return Pair.create(arrayList, arrayList2);
    }

    /* renamed from: c */
    public static boolean m697c(String str) {
        return Build.VERSION.SDK_INT < 23 || ContextCompat.checkSelfPermission(C4195m.m4792Y(), str) == 0;
    }

    /* renamed from: d */
    public static void m698d() {
        String packageName = C4195m.m4792Y().getPackageName();
        Intent intent = new Intent("android.settings.APPLICATION_DETAILS_SETTINGS");
        intent.setData(Uri.parse("package:" + packageName));
        Intent addFlags = intent.addFlags(Label.FORWARD_REFERENCE_TYPE_SHORT);
        if (C1550t.m729f(addFlags)) {
            C4195m.m4792Y().startActivity(addFlags);
        }
    }

    /* renamed from: a */
    public final void m699a(Activity activity) {
        for (String str : this.f1741h) {
            if (m697c(str)) {
                this.f1742i.add(str);
            } else {
                this.f1743j.add(str);
                if (!activity.shouldShowRequestPermissionRationale(str)) {
                    this.f1744k.add(str);
                }
            }
        }
    }

    /* renamed from: e */
    public void m700e() {
        String[] strArr = this.f1737d;
        if (strArr == null || strArr.length <= 0) {
            return;
        }
        this.f1740g = new LinkedHashSet();
        this.f1741h = new ArrayList();
        this.f1742i = new ArrayList();
        this.f1743j = new ArrayList();
        this.f1744k = new ArrayList();
        Pair<List<String>, List<String>> m696b = m696b(this.f1737d);
        this.f1740g.addAll((Collection) m696b.first);
        this.f1743j.addAll((Collection) m696b.second);
        if (Build.VERSION.SDK_INT < 23) {
            this.f1742i.addAll(this.f1740g);
            m701f();
            return;
        }
        for (String str : this.f1740g) {
            if (m697c(str)) {
                this.f1742i.add(str);
            } else {
                this.f1741h.add(str);
            }
        }
        if (this.f1741h.isEmpty()) {
            m701f();
            return;
        }
        b bVar = b.f1746e;
        Map<UtilsTransActivity, UtilsTransActivity.AbstractC3220a> map = UtilsTransActivity.f8840c;
        Intent intent = new Intent(C4195m.m4792Y(), (Class<?>) UtilsTransActivity.class);
        intent.putExtra("extra_delegate", bVar);
        intent.putExtra("TYPE", 1);
        intent.addFlags(Label.FORWARD_REFERENCE_TYPE_SHORT);
        C4195m.m4792Y().startActivity(intent);
    }

    /* renamed from: f */
    public final void m701f() {
        d dVar = this.f1739f;
        if (dVar != null) {
            dVar.mo300a(this.f1743j.isEmpty(), this.f1742i, this.f1744k, this.f1743j);
            this.f1739f = null;
        }
    }
}
