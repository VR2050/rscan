package androidx.fragment.app;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;

/* JADX INFO: renamed from: androidx.fragment.app.e, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class DialogInterfaceOnCancelListenerC0293e extends Fragment implements DialogInterface.OnCancelListener, DialogInterface.OnDismissListener {

    /* JADX INFO: renamed from: d0, reason: collision with root package name */
    private Handler f4963d0;

    /* JADX INFO: renamed from: m0, reason: collision with root package name */
    private boolean f4972m0;

    /* JADX INFO: renamed from: o0, reason: collision with root package name */
    private Dialog f4974o0;

    /* JADX INFO: renamed from: p0, reason: collision with root package name */
    private boolean f4975p0;

    /* JADX INFO: renamed from: q0, reason: collision with root package name */
    private boolean f4976q0;

    /* JADX INFO: renamed from: r0, reason: collision with root package name */
    private boolean f4977r0;

    /* JADX INFO: renamed from: e0, reason: collision with root package name */
    private Runnable f4964e0 = new a();

    /* JADX INFO: renamed from: f0, reason: collision with root package name */
    private DialogInterface.OnCancelListener f4965f0 = new b();

    /* JADX INFO: renamed from: g0, reason: collision with root package name */
    private DialogInterface.OnDismissListener f4966g0 = new c();

    /* JADX INFO: renamed from: h0, reason: collision with root package name */
    private int f4967h0 = 0;

    /* JADX INFO: renamed from: i0, reason: collision with root package name */
    private int f4968i0 = 0;

    /* JADX INFO: renamed from: j0, reason: collision with root package name */
    private boolean f4969j0 = true;

    /* JADX INFO: renamed from: k0, reason: collision with root package name */
    private boolean f4970k0 = true;

    /* JADX INFO: renamed from: l0, reason: collision with root package name */
    private int f4971l0 = -1;

    /* JADX INFO: renamed from: n0, reason: collision with root package name */
    private androidx.lifecycle.p f4973n0 = new d();

    /* JADX INFO: renamed from: s0, reason: collision with root package name */
    private boolean f4978s0 = false;

    /* JADX INFO: renamed from: androidx.fragment.app.e$a */
    class a implements Runnable {
        a() {
        }

        @Override // java.lang.Runnable
        public void run() {
            DialogInterfaceOnCancelListenerC0293e.this.f4966g0.onDismiss(DialogInterfaceOnCancelListenerC0293e.this.f4974o0);
        }
    }

    /* JADX INFO: renamed from: androidx.fragment.app.e$b */
    class b implements DialogInterface.OnCancelListener {
        b() {
        }

        @Override // android.content.DialogInterface.OnCancelListener
        public void onCancel(DialogInterface dialogInterface) {
            if (DialogInterfaceOnCancelListenerC0293e.this.f4974o0 != null) {
                DialogInterfaceOnCancelListenerC0293e dialogInterfaceOnCancelListenerC0293e = DialogInterfaceOnCancelListenerC0293e.this;
                dialogInterfaceOnCancelListenerC0293e.onCancel(dialogInterfaceOnCancelListenerC0293e.f4974o0);
            }
        }
    }

    /* JADX INFO: renamed from: androidx.fragment.app.e$c */
    class c implements DialogInterface.OnDismissListener {
        c() {
        }

        @Override // android.content.DialogInterface.OnDismissListener
        public void onDismiss(DialogInterface dialogInterface) {
            if (DialogInterfaceOnCancelListenerC0293e.this.f4974o0 != null) {
                DialogInterfaceOnCancelListenerC0293e dialogInterfaceOnCancelListenerC0293e = DialogInterfaceOnCancelListenerC0293e.this;
                dialogInterfaceOnCancelListenerC0293e.onDismiss(dialogInterfaceOnCancelListenerC0293e.f4974o0);
            }
        }
    }

    /* JADX INFO: renamed from: androidx.fragment.app.e$d */
    class d implements androidx.lifecycle.p {
        d() {
        }

        @Override // androidx.lifecycle.p
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public void a(androidx.lifecycle.k kVar) {
            if (kVar == null || !DialogInterfaceOnCancelListenerC0293e.this.f4970k0) {
                return;
            }
            View viewM1 = DialogInterfaceOnCancelListenerC0293e.this.m1();
            if (viewM1.getParent() != null) {
                throw new IllegalStateException("DialogFragment can not be attached to a container view");
            }
            if (DialogInterfaceOnCancelListenerC0293e.this.f4974o0 != null) {
                if (x.G0(3)) {
                    Log.d("FragmentManager", "DialogFragment " + this + " setting the content view on " + DialogInterfaceOnCancelListenerC0293e.this.f4974o0);
                }
                DialogInterfaceOnCancelListenerC0293e.this.f4974o0.setContentView(viewM1);
            }
        }
    }

    /* JADX INFO: renamed from: androidx.fragment.app.e$e, reason: collision with other inner class name */
    class C0072e extends AbstractC0300l {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ AbstractC0300l f4983b;

        C0072e(AbstractC0300l abstractC0300l) {
            this.f4983b = abstractC0300l;
        }

        @Override // androidx.fragment.app.AbstractC0300l
        public View f(int i3) {
            return this.f4983b.h() ? this.f4983b.f(i3) : DialogInterfaceOnCancelListenerC0293e.this.F1(i3);
        }

        @Override // androidx.fragment.app.AbstractC0300l
        public boolean h() {
            return this.f4983b.h() || DialogInterfaceOnCancelListenerC0293e.this.G1();
        }
    }

    private void C1(boolean z3, boolean z4, boolean z5) {
        if (this.f4976q0) {
            return;
        }
        this.f4976q0 = true;
        this.f4977r0 = false;
        Dialog dialog = this.f4974o0;
        if (dialog != null) {
            dialog.setOnDismissListener(null);
            this.f4974o0.dismiss();
            if (!z4) {
                if (Looper.myLooper() == this.f4963d0.getLooper()) {
                    onDismiss(this.f4974o0);
                } else {
                    this.f4963d0.post(this.f4964e0);
                }
            }
        }
        this.f4975p0 = true;
        if (this.f4971l0 >= 0) {
            if (z5) {
                D().Z0(this.f4971l0, 1);
            } else {
                D().X0(this.f4971l0, 1, z3);
            }
            this.f4971l0 = -1;
            return;
        }
        F fO = D().o();
        fO.m(true);
        fO.l(this);
        if (z5) {
            fO.h();
        } else if (z3) {
            fO.g();
        } else {
            fO.f();
        }
    }

    private void H1(Bundle bundle) {
        if (this.f4970k0 && !this.f4978s0) {
            try {
                this.f4972m0 = true;
                Dialog dialogE1 = E1(bundle);
                this.f4974o0 = dialogE1;
                if (this.f4970k0) {
                    J1(dialogE1, this.f4967h0);
                    Context contextO = o();
                    if (contextO instanceof Activity) {
                        this.f4974o0.setOwnerActivity((Activity) contextO);
                    }
                    this.f4974o0.setCancelable(this.f4969j0);
                    this.f4974o0.setOnCancelListener(this.f4965f0);
                    this.f4974o0.setOnDismissListener(this.f4966g0);
                    this.f4978s0 = true;
                } else {
                    this.f4974o0 = null;
                }
                this.f4972m0 = false;
            } catch (Throwable th) {
                this.f4972m0 = false;
                throw th;
            }
        }
    }

    public void B1() {
        C1(false, false, false);
    }

    public int D1() {
        return this.f4968i0;
    }

    public Dialog E1(Bundle bundle) {
        if (x.G0(3)) {
            Log.d("FragmentManager", "onCreateDialog called for DialogFragment " + this);
        }
        return new androidx.activity.i(l1(), D1());
    }

    @Override // androidx.fragment.app.Fragment
    public void F0(Bundle bundle) {
        super.F0(bundle);
        Dialog dialog = this.f4974o0;
        if (dialog != null) {
            Bundle bundleOnSaveInstanceState = dialog.onSaveInstanceState();
            bundleOnSaveInstanceState.putBoolean("android:dialogShowing", false);
            bundle.putBundle("android:savedDialogState", bundleOnSaveInstanceState);
        }
        int i3 = this.f4967h0;
        if (i3 != 0) {
            bundle.putInt("android:style", i3);
        }
        int i4 = this.f4968i0;
        if (i4 != 0) {
            bundle.putInt("android:theme", i4);
        }
        boolean z3 = this.f4969j0;
        if (!z3) {
            bundle.putBoolean("android:cancelable", z3);
        }
        boolean z4 = this.f4970k0;
        if (!z4) {
            bundle.putBoolean("android:showsDialog", z4);
        }
        int i5 = this.f4971l0;
        if (i5 != -1) {
            bundle.putInt("android:backStackId", i5);
        }
    }

    View F1(int i3) {
        Dialog dialog = this.f4974o0;
        if (dialog != null) {
            return dialog.findViewById(i3);
        }
        return null;
    }

    @Override // androidx.fragment.app.Fragment
    public void G0() {
        super.G0();
        Dialog dialog = this.f4974o0;
        if (dialog != null) {
            this.f4975p0 = false;
            dialog.show();
            View decorView = this.f4974o0.getWindow().getDecorView();
            androidx.lifecycle.D.a(decorView, this);
            androidx.lifecycle.E.a(decorView, this);
            F.e.a(decorView, this);
        }
    }

    boolean G1() {
        return this.f4978s0;
    }

    @Override // androidx.fragment.app.Fragment
    public void H0() {
        super.H0();
        Dialog dialog = this.f4974o0;
        if (dialog != null) {
            dialog.hide();
        }
    }

    public void I1(boolean z3) {
        this.f4969j0 = z3;
        Dialog dialog = this.f4974o0;
        if (dialog != null) {
            dialog.setCancelable(z3);
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void J0(Bundle bundle) {
        Bundle bundle2;
        super.J0(bundle);
        if (this.f4974o0 == null || bundle == null || (bundle2 = bundle.getBundle("android:savedDialogState")) == null) {
            return;
        }
        this.f4974o0.onRestoreInstanceState(bundle2);
    }

    public void J1(Dialog dialog, int i3) {
        if (i3 != 1 && i3 != 2) {
            if (i3 != 3) {
                return;
            }
            Window window = dialog.getWindow();
            if (window != null) {
                window.addFlags(24);
            }
        }
        dialog.requestWindowFeature(1);
    }

    public void K1(x xVar, String str) {
        this.f4976q0 = false;
        this.f4977r0 = true;
        F fO = xVar.o();
        fO.m(true);
        fO.d(this, str);
        fO.f();
    }

    @Override // androidx.fragment.app.Fragment
    void Q0(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
        Bundle bundle2;
        super.Q0(layoutInflater, viewGroup, bundle);
        if (this.f4764J != null || this.f4974o0 == null || bundle == null || (bundle2 = bundle.getBundle("android:savedDialogState")) == null) {
            return;
        }
        this.f4974o0.onRestoreInstanceState(bundle2);
    }

    @Override // androidx.fragment.app.Fragment
    AbstractC0300l d() {
        return new C0072e(super.d());
    }

    @Override // androidx.fragment.app.Fragment
    public void d0(Bundle bundle) {
        super.d0(bundle);
    }

    @Override // androidx.fragment.app.Fragment
    public void g0(Context context) {
        super.g0(context);
        R().e(this.f4973n0);
        if (this.f4977r0) {
            return;
        }
        this.f4976q0 = false;
    }

    @Override // androidx.fragment.app.Fragment
    public void j0(Bundle bundle) {
        super.j0(bundle);
        this.f4963d0 = new Handler();
        this.f4970k0 = this.f4807z == 0;
        if (bundle != null) {
            this.f4967h0 = bundle.getInt("android:style", 0);
            this.f4968i0 = bundle.getInt("android:theme", 0);
            this.f4969j0 = bundle.getBoolean("android:cancelable", true);
            this.f4970k0 = bundle.getBoolean("android:showsDialog", this.f4970k0);
            this.f4971l0 = bundle.getInt("android:backStackId", -1);
        }
    }

    @Override // android.content.DialogInterface.OnCancelListener
    public void onCancel(DialogInterface dialogInterface) {
    }

    @Override // android.content.DialogInterface.OnDismissListener
    public void onDismiss(DialogInterface dialogInterface) {
        if (this.f4975p0) {
            return;
        }
        if (x.G0(3)) {
            Log.d("FragmentManager", "onDismiss called for DialogFragment " + this);
        }
        C1(true, true, false);
    }

    @Override // androidx.fragment.app.Fragment
    public void q0() {
        super.q0();
        Dialog dialog = this.f4974o0;
        if (dialog != null) {
            this.f4975p0 = true;
            dialog.setOnDismissListener(null);
            this.f4974o0.dismiss();
            if (!this.f4976q0) {
                onDismiss(this.f4974o0);
            }
            this.f4974o0 = null;
            this.f4978s0 = false;
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void r0() {
        super.r0();
        if (!this.f4977r0 && !this.f4976q0) {
            this.f4976q0 = true;
        }
        R().h(this.f4973n0);
    }

    @Override // androidx.fragment.app.Fragment
    public LayoutInflater s0(Bundle bundle) {
        LayoutInflater layoutInflaterS0 = super.s0(bundle);
        if (this.f4970k0 && !this.f4972m0) {
            H1(bundle);
            if (x.G0(2)) {
                Log.d("FragmentManager", "get layout inflater for DialogFragment " + this + " from dialog context");
            }
            Dialog dialog = this.f4974o0;
            return dialog != null ? layoutInflaterS0.cloneInContext(dialog.getContext()) : layoutInflaterS0;
        }
        if (x.G0(2)) {
            String str = "getting layout inflater for DialogFragment " + this;
            if (this.f4970k0) {
                Log.d("FragmentManager", "mCreatingDialog = true: " + str);
            } else {
                Log.d("FragmentManager", "mShowsDialog = false: " + str);
            }
        }
        return layoutInflaterS0;
    }
}
