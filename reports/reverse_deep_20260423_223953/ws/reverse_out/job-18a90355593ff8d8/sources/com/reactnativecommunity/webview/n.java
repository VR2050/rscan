package com.reactnativecommunity.webview;

import android.app.Activity;
import android.app.DownloadManager;
import android.content.ComponentCallbacks2;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.os.Parcelable;
import android.util.Log;
import android.webkit.MimeTypeMap;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.widget.Toast;
import com.facebook.react.bridge.ActivityEventListener;
import com.facebook.react.bridge.ReactApplicationContext;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicReference;

/* JADX INFO: loaded from: classes.dex */
public class n implements ActivityEventListener {

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    protected static final d f8646g = new d();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final ReactApplicationContext f8647a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private DownloadManager.Request f8648b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private ValueCallback f8649c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private ValueCallback f8650d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private File f8651e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private File f8652f;

    class a implements A1.g {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ String f8653b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ String f8654c;

        a(String str, String str2) {
            this.f8653b = str;
            this.f8654c = str2;
        }

        @Override // A1.g
        public boolean onRequestPermissionsResult(int i3, String[] strArr, int[] iArr) {
            if (i3 != 1) {
                return false;
            }
            if (iArr.length <= 0 || iArr[0] != 0) {
                Toast.makeText(n.this.f8647a, this.f8654c, 1).show();
            } else if (n.this.f8648b != null) {
                n.this.h(this.f8653b);
            }
            return true;
        }
    }

    static /* synthetic */ class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        static final /* synthetic */ int[] f8656a;

        static {
            int[] iArr = new int[c.values().length];
            f8656a = iArr;
            try {
                iArr[c.IMAGE.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f8656a[c.VIDEO.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
        }
    }

    private enum c {
        DEFAULT("*/*"),
        IMAGE("image"),
        VIDEO("video");


        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final String f8661b;

        c(String str) {
            this.f8661b = str;
        }
    }

    protected static class d {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private double f8662a = 1.0d;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final HashMap f8663b = new HashMap();

        protected enum a {
            UNDECIDED,
            SHOULD_OVERRIDE,
            DO_NOT_OVERRIDE
        }

        protected d() {
        }

        public synchronized AtomicReference a(Double d3) {
            return (AtomicReference) this.f8663b.get(d3);
        }

        public synchronized q.d b() {
            double d3;
            AtomicReference atomicReference;
            d3 = this.f8662a;
            this.f8662a = 1.0d + d3;
            atomicReference = new AtomicReference(a.UNDECIDED);
            this.f8663b.put(Double.valueOf(d3), atomicReference);
            return new q.d(Double.valueOf(d3), atomicReference);
        }

        public synchronized void c(Double d3) {
            this.f8663b.remove(d3);
        }
    }

    public n(ReactApplicationContext reactApplicationContext) {
        this.f8647a = reactApplicationContext;
        reactApplicationContext.addActivityEventListener(this);
    }

    private Boolean c(String str) {
        if (str.matches("\\.\\w+")) {
            str = m(str.replace(".", ""));
        }
        return Boolean.valueOf(str.isEmpty() || str.toLowerCase().contains(c.IMAGE.f8661b));
    }

    private Boolean d(String[] strArr) {
        String[] strArrI = i(strArr);
        return Boolean.valueOf(g(strArrI, c.DEFAULT.f8661b).booleanValue() || g(strArrI, c.IMAGE.f8661b).booleanValue());
    }

    private Boolean e(String str) {
        if (str.matches("\\.\\w+")) {
            str = m(str.replace(".", ""));
        }
        return Boolean.valueOf(str.isEmpty() || str.toLowerCase().contains(c.VIDEO.f8661b));
    }

    private Boolean f(String[] strArr) {
        String[] strArrI = i(strArr);
        return Boolean.valueOf(g(strArrI, c.DEFAULT.f8661b).booleanValue() || g(strArrI, c.VIDEO.f8661b).booleanValue());
    }

    private Boolean g(String[] strArr, String str) {
        for (String str2 : strArr) {
            if (str2.contains(str)) {
                return Boolean.TRUE;
            }
        }
        return Boolean.FALSE;
    }

    private String[] i(String[] strArr) {
        if (w(strArr).booleanValue()) {
            return new String[]{c.DEFAULT.f8661b};
        }
        String[] strArr2 = new String[strArr.length];
        for (int i3 = 0; i3 < strArr.length; i3++) {
            String str = strArr[i3];
            if (str.matches("\\.\\w+")) {
                String strM = m(str.replace(".", ""));
                if (strM != null) {
                    strArr2[i3] = strM;
                } else {
                    strArr2[i3] = str;
                }
            } else {
                strArr2[i3] = str;
            }
        }
        return strArr2;
    }

    private Intent k(String str) {
        String strM = str.isEmpty() ? c.DEFAULT.f8661b : str;
        if (str.matches("\\.\\w+")) {
            strM = m(str.replace(".", ""));
        }
        Intent intent = new Intent("android.intent.action.GET_CONTENT");
        intent.addCategory("android.intent.category.OPENABLE");
        intent.setType(strM);
        return intent;
    }

    private Intent l(String[] strArr, boolean z3) {
        Intent intent = new Intent("android.intent.action.GET_CONTENT");
        intent.addCategory("android.intent.category.OPENABLE");
        intent.setType(c.DEFAULT.f8661b);
        intent.putExtra("android.intent.extra.MIME_TYPES", i(strArr));
        intent.putExtra("android.intent.extra.ALLOW_MULTIPLE", z3);
        return intent;
    }

    private String m(String str) {
        if (str != null) {
            return MimeTypeMap.getSingleton().getMimeTypeFromExtension(str);
        }
        return null;
    }

    private A1.f o() {
        ComponentCallbacks2 currentActivity = this.f8647a.getCurrentActivity();
        if (currentActivity == null) {
            throw new IllegalStateException("Tried to use permissions API while not attached to an Activity.");
        }
        if (currentActivity instanceof A1.f) {
            return (A1.f) currentActivity;
        }
        throw new IllegalStateException("Tried to use permissions API but the host Activity doesn't implement PermissionAwareActivity.");
    }

    private A1.g s(String str, String str2) {
        return new a(str, str2);
    }

    private Boolean w(String[] strArr) {
        String str;
        boolean z3 = true;
        if (strArr.length != 0 && (strArr.length != 1 || (str = strArr[0]) == null || str.length() != 0)) {
            z3 = false;
        }
        return Boolean.valueOf(z3);
    }

    public boolean A(String[] strArr, boolean z3, ValueCallback valueCallback, boolean z4) {
        Intent intentR;
        this.f8650d = valueCallback;
        Activity currentActivity = this.f8647a.getCurrentActivity();
        ArrayList arrayList = new ArrayList();
        Intent intentP = null;
        if (!v()) {
            if (d(strArr).booleanValue() && (intentP = p()) != null) {
                arrayList.add(intentP);
            }
            if (f(strArr).booleanValue() && (intentR = r()) != null) {
                arrayList.add(intentR);
            }
        }
        Intent intent = new Intent("android.intent.action.CHOOSER");
        if (!z4) {
            intent.putExtra("android.intent.extra.INTENT", l(strArr, z3));
            intent.putExtra("android.intent.extra.INITIAL_INTENTS", (Parcelable[]) arrayList.toArray(new Parcelable[0]));
            intentP = intent;
        }
        if (intentP == null) {
            Log.w(NativeRNCWebViewModuleSpec.NAME, "there is no Camera permission");
        } else if (intentP.resolveActivity(currentActivity.getPackageManager()) != null) {
            currentActivity.startActivityForResult(intentP, 1);
        } else {
            Log.w(NativeRNCWebViewModuleSpec.NAME, "there is no Activity to handle this Intent");
        }
        return true;
    }

    public void h(String str) {
        try {
            ((DownloadManager) this.f8647a.getSystemService("download")).enqueue(this.f8648b);
            Toast.makeText(this.f8647a, str, 1).show();
        } catch (IllegalArgumentException | SecurityException e3) {
            Log.w(NativeRNCWebViewModuleSpec.NAME, "Unsupported URI, aborting download", e3);
        }
    }

    public File j(c cVar) {
        String str;
        String str2;
        int i3 = b.f8656a[cVar.ordinal()];
        if (i3 == 1) {
            String str3 = Environment.DIRECTORY_PICTURES;
            str = "image-";
            str2 = ".jpg";
        } else if (i3 != 2) {
            str = "";
            str2 = "";
        } else {
            String str4 = Environment.DIRECTORY_MOVIES;
            str = "video-";
            str2 = ".mp4";
        }
        StringBuilder sb = new StringBuilder();
        sb.append(str);
        sb.append(String.valueOf(System.currentTimeMillis()));
        sb.append(str2);
        return File.createTempFile(str, str2, this.f8647a.getExternalFilesDir(null));
    }

    public Uri n(File file) {
        String packageName = this.f8647a.getPackageName();
        return androidx.core.content.b.h(this.f8647a, packageName + ".fileprovider", file);
    }

    @Override // com.facebook.react.bridge.ActivityEventListener
    public void onActivityResult(Activity activity, int i3, int i4, Intent intent) {
        if (this.f8650d == null && this.f8649c == null) {
            return;
        }
        File file = this.f8651e;
        boolean z3 = false;
        boolean z4 = file != null && file.length() > 0;
        File file2 = this.f8652f;
        if (file2 != null && file2.length() > 0) {
            z3 = true;
        }
        if (i3 != 1) {
            if (i3 == 3) {
                if (i4 != -1) {
                    this.f8649c.onReceiveValue(null);
                } else if (z4) {
                    this.f8649c.onReceiveValue(n(this.f8651e));
                } else if (z3) {
                    this.f8649c.onReceiveValue(n(this.f8652f));
                } else {
                    this.f8649c.onReceiveValue(intent.getData());
                }
            }
        } else if (i4 != -1) {
            ValueCallback valueCallback = this.f8650d;
            if (valueCallback != null) {
                valueCallback.onReceiveValue(null);
            }
        } else if (z4) {
            this.f8650d.onReceiveValue(new Uri[]{n(this.f8651e)});
        } else if (z3) {
            this.f8650d.onReceiveValue(new Uri[]{n(this.f8652f)});
        } else {
            this.f8650d.onReceiveValue(q(intent, i4));
        }
        File file3 = this.f8651e;
        if (file3 != null && !z4) {
            file3.delete();
        }
        File file4 = this.f8652f;
        if (file4 != null && !z3) {
            file4.delete();
        }
        this.f8650d = null;
        this.f8649c = null;
        this.f8651e = null;
        this.f8652f = null;
    }

    @Override // com.facebook.react.bridge.ActivityEventListener
    public void onNewIntent(Intent intent) {
    }

    public Intent p() {
        Intent intent;
        Throwable e3;
        Uri uriN;
        try {
            File fileJ = j(c.IMAGE);
            this.f8651e = fileJ;
            uriN = n(fileJ);
            intent = new Intent("android.media.action.IMAGE_CAPTURE");
        } catch (IOException | IllegalArgumentException e4) {
            intent = null;
            e3 = e4;
        }
        try {
            intent.putExtra("output", uriN);
        } catch (IOException e5) {
            e3 = e5;
            Log.e("CREATE FILE", "Error occurred while creating the File", e3);
            e3.printStackTrace();
        } catch (IllegalArgumentException e6) {
            e3 = e6;
            Log.e("CREATE FILE", "Error occurred while creating the File", e3);
            e3.printStackTrace();
        }
        return intent;
    }

    public Uri[] q(Intent intent, int i3) {
        if (intent == null) {
            return null;
        }
        if (intent.getClipData() == null) {
            if (intent.getData() == null || i3 != -1) {
                return null;
            }
            return WebChromeClient.FileChooserParams.parseResult(i3, intent);
        }
        int itemCount = intent.getClipData().getItemCount();
        Uri[] uriArr = new Uri[itemCount];
        for (int i4 = 0; i4 < itemCount; i4++) {
            uriArr[i4] = intent.getClipData().getItemAt(i4).getUri();
        }
        return uriArr;
    }

    public Intent r() {
        Intent intent;
        Throwable e3;
        Uri uriN;
        try {
            File fileJ = j(c.VIDEO);
            this.f8652f = fileJ;
            uriN = n(fileJ);
            intent = new Intent("android.media.action.VIDEO_CAPTURE");
        } catch (IOException | IllegalArgumentException e4) {
            intent = null;
            e3 = e4;
        }
        try {
            intent.putExtra("output", uriN);
        } catch (IOException e5) {
            e3 = e5;
            Log.e("CREATE FILE", "Error occurred while creating the File", e3);
            e3.printStackTrace();
        } catch (IllegalArgumentException e6) {
            e3 = e6;
            Log.e("CREATE FILE", "Error occurred while creating the File", e3);
            e3.printStackTrace();
        }
        return intent;
    }

    public boolean t(String str, String str2) {
        Activity currentActivity = this.f8647a.getCurrentActivity();
        if (Build.VERSION.SDK_INT > 28) {
            return true;
        }
        boolean z3 = androidx.core.content.a.a(currentActivity, "android.permission.WRITE_EXTERNAL_STORAGE") == 0;
        if (!z3) {
            o().i(new String[]{"android.permission.WRITE_EXTERNAL_STORAGE"}, 1, s(str, str2));
        }
        return z3;
    }

    public boolean u() {
        return true;
    }

    protected boolean v() {
        Activity currentActivity = this.f8647a.getCurrentActivity();
        try {
            if (Arrays.asList(currentActivity.getPackageManager().getPackageInfo(currentActivity.getApplicationContext().getPackageName(), 4096).requestedPermissions).contains("android.permission.CAMERA")) {
                if (androidx.core.content.a.a(currentActivity, "android.permission.CAMERA") != 0) {
                    return true;
                }
            }
            return false;
        } catch (PackageManager.NameNotFoundException unused) {
            return true;
        }
    }

    public void x(DownloadManager.Request request) {
        this.f8648b = request;
    }

    public void y(boolean z3, double d3) {
        AtomicReference atomicReferenceA = f8646g.a(Double.valueOf(d3));
        if (atomicReferenceA != null) {
            synchronized (atomicReferenceA) {
                try {
                    atomicReferenceA.set(z3 ? d.a.DO_NOT_OVERRIDE : d.a.SHOULD_OVERRIDE);
                    atomicReferenceA.notify();
                } finally {
                }
            }
        }
    }

    public void z(String str, ValueCallback valueCallback) {
        Intent intentR;
        Intent intentP;
        this.f8649c = valueCallback;
        Activity currentActivity = this.f8647a.getCurrentActivity();
        Intent intentCreateChooser = Intent.createChooser(k(str), "");
        ArrayList arrayList = new ArrayList();
        if (c(str).booleanValue() && (intentP = p()) != null) {
            arrayList.add(intentP);
        }
        if (e(str).booleanValue() && (intentR = r()) != null) {
            arrayList.add(intentR);
        }
        intentCreateChooser.putExtra("android.intent.extra.INITIAL_INTENTS", (Parcelable[]) arrayList.toArray(new Parcelable[0]));
        if (intentCreateChooser.resolveActivity(currentActivity.getPackageManager()) != null) {
            currentActivity.startActivityForResult(intentCreateChooser, 3);
        } else {
            Log.w(NativeRNCWebViewModuleSpec.NAME, "there is no Activity to handle this Intent");
        }
    }
}
