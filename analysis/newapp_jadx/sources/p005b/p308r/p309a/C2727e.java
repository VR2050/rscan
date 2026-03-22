package p005b.p308r.p309a;

import android.app.Dialog;
import android.content.Context;
import android.graphics.drawable.ColorDrawable;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.TextView;
import com.kaopiz.kprogresshud.BackgroundLayout;
import com.kaopiz.kprogresshud.R$color;
import com.kaopiz.kprogresshud.R$id;
import com.kaopiz.kprogresshud.R$layout;
import java.util.Objects;
import p005b.p085c.p088b.p089a.C1345b;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: b.r.a.e */
/* loaded from: classes2.dex */
public class C2727e {

    /* renamed from: a */
    public a f7407a;

    /* renamed from: b */
    public int f7408b;

    /* renamed from: d */
    public Context f7410d;

    /* renamed from: e */
    public int f7411e = 1;

    /* renamed from: c */
    public float f7409c = 10.0f;

    /* renamed from: f */
    public boolean f7412f = false;

    /* renamed from: b.r.a.e$a */
    public class a extends Dialog {

        /* renamed from: c */
        public InterfaceC2725c f7413c;

        /* renamed from: e */
        public InterfaceC2726d f7414e;

        /* renamed from: f */
        public View f7415f;

        /* renamed from: g */
        public TextView f7416g;

        /* renamed from: h */
        public TextView f7417h;

        /* renamed from: i */
        public String f7418i;

        /* renamed from: j */
        public String f7419j;

        /* renamed from: k */
        public FrameLayout f7420k;

        /* renamed from: l */
        public BackgroundLayout f7421l;

        /* renamed from: m */
        public int f7422m;

        /* renamed from: n */
        public int f7423n;

        public a(Context context) {
            super(context);
            this.f7422m = -1;
            this.f7423n = -1;
        }

        @Override // android.app.Dialog
        public void onCreate(Bundle bundle) {
            super.onCreate(bundle);
            requestWindowFeature(1);
            setContentView(R$layout.kprogresshud_hud);
            Window window = getWindow();
            window.setBackgroundDrawable(new ColorDrawable(0));
            window.addFlags(2);
            WindowManager.LayoutParams attributes = window.getAttributes();
            Objects.requireNonNull(C2727e.this);
            attributes.dimAmount = 0.0f;
            attributes.gravity = 17;
            window.setAttributes(attributes);
            setCanceledOnTouchOutside(false);
            BackgroundLayout backgroundLayout = (BackgroundLayout) findViewById(R$id.background);
            this.f7421l = backgroundLayout;
            int i2 = C2727e.this.f7408b;
            backgroundLayout.f10150e = i2;
            backgroundLayout.m4519a(i2, backgroundLayout.f10149c);
            BackgroundLayout backgroundLayout2 = this.f7421l;
            float m2434U = C2354n.m2434U(C2727e.this.f7409c, backgroundLayout2.getContext());
            backgroundLayout2.f10149c = m2434U;
            backgroundLayout2.m4519a(backgroundLayout2.f10150e, m2434U);
            this.f7420k = (FrameLayout) findViewById(R$id.container);
            View view = this.f7415f;
            if (view != null) {
                this.f7420k.addView(view, new ViewGroup.LayoutParams(-2, -2));
            }
            InterfaceC2725c interfaceC2725c = this.f7413c;
            if (interfaceC2725c != null) {
                Objects.requireNonNull(C2727e.this);
                interfaceC2725c.mo3239a(0);
            }
            InterfaceC2726d interfaceC2726d = this.f7414e;
            if (interfaceC2726d != null) {
                interfaceC2726d.setAnimationSpeed(C2727e.this.f7411e);
            }
            TextView textView = (TextView) findViewById(R$id.label);
            this.f7416g = textView;
            String str = this.f7418i;
            int i3 = this.f7422m;
            this.f7418i = str;
            this.f7422m = i3;
            if (textView != null) {
                if (str != null) {
                    textView.setText(str);
                    this.f7416g.setTextColor(i3);
                    this.f7416g.setVisibility(0);
                } else {
                    textView.setVisibility(8);
                }
            }
            TextView textView2 = (TextView) findViewById(R$id.details_label);
            this.f7417h = textView2;
            String str2 = this.f7419j;
            int i4 = this.f7423n;
            this.f7419j = str2;
            this.f7423n = i4;
            if (textView2 != null) {
                if (str2 == null) {
                    textView2.setVisibility(8);
                    return;
                }
                textView2.setText(str2);
                this.f7417h.setTextColor(i4);
                this.f7417h.setVisibility(0);
            }
        }
    }

    public C2727e(Context context) {
        this.f7410d = context;
        this.f7407a = new a(context);
        this.f7408b = context.getResources().getColor(R$color.kprogresshud_default_color);
        m3241b(1);
    }

    /* renamed from: a */
    public boolean m3240a() {
        a aVar = this.f7407a;
        return aVar != null && aVar.isShowing();
    }

    /* renamed from: b */
    public C2727e m3241b(int i2) {
        int m350b = C1345b.m350b(i2);
        View c2724b = m350b != 0 ? m350b != 1 ? m350b != 2 ? m350b != 3 ? null : new C2724b(this.f7410d) : new C2723a(this.f7410d) : new C2728f(this.f7410d) : new C2730h(this.f7410d);
        a aVar = this.f7407a;
        Objects.requireNonNull(aVar);
        if (c2724b != null) {
            if (c2724b instanceof InterfaceC2725c) {
                aVar.f7413c = (InterfaceC2725c) c2724b;
            }
            if (c2724b instanceof InterfaceC2726d) {
                aVar.f7414e = (InterfaceC2726d) c2724b;
            }
            aVar.f7415f = c2724b;
            if (aVar.isShowing()) {
                aVar.f7420k.removeAllViews();
                aVar.f7420k.addView(c2724b, new ViewGroup.LayoutParams(-2, -2));
            }
        }
        return this;
    }
}
