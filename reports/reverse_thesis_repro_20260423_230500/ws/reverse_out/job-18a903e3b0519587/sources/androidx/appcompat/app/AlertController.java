package androidx.appcompat.app;

import android.R;
import android.content.Context;
import android.content.DialogInterface;
import android.content.res.TypedArray;
import android.database.Cursor;
import android.graphics.drawable.Drawable;
import android.os.Handler;
import android.os.Message;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.ViewStub;
import android.view.Window;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckedTextView;
import android.widget.CursorAdapter;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListAdapter;
import android.widget.ListView;
import android.widget.SimpleCursorAdapter;
import android.widget.TextView;
import androidx.appcompat.widget.T;
import androidx.core.view.V;
import androidx.core.widget.NestedScrollView;
import d.AbstractC0502a;
import java.lang.ref.WeakReference;

/* JADX INFO: loaded from: classes.dex */
class AlertController {

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    NestedScrollView f3022A;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    private Drawable f3024C;

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    private ImageView f3025D;

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    private TextView f3026E;

    /* JADX INFO: renamed from: F, reason: collision with root package name */
    private TextView f3027F;

    /* JADX INFO: renamed from: G, reason: collision with root package name */
    private View f3028G;

    /* JADX INFO: renamed from: H, reason: collision with root package name */
    ListAdapter f3029H;

    /* JADX INFO: renamed from: J, reason: collision with root package name */
    private int f3031J;

    /* JADX INFO: renamed from: K, reason: collision with root package name */
    private int f3032K;

    /* JADX INFO: renamed from: L, reason: collision with root package name */
    int f3033L;

    /* JADX INFO: renamed from: M, reason: collision with root package name */
    int f3034M;

    /* JADX INFO: renamed from: N, reason: collision with root package name */
    int f3035N;

    /* JADX INFO: renamed from: O, reason: collision with root package name */
    int f3036O;

    /* JADX INFO: renamed from: P, reason: collision with root package name */
    private boolean f3037P;

    /* JADX INFO: renamed from: R, reason: collision with root package name */
    Handler f3039R;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Context f3041a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    final r f3042b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Window f3043c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final int f3044d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private CharSequence f3045e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private CharSequence f3046f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    ListView f3047g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private View f3048h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private int f3049i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private int f3050j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private int f3051k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private int f3052l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private int f3053m;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    Button f3055o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private CharSequence f3056p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    Message f3057q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private Drawable f3058r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    Button f3059s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private CharSequence f3060t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    Message f3061u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private Drawable f3062v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    Button f3063w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private CharSequence f3064x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    Message f3065y;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private Drawable f3066z;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private boolean f3054n = false;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private int f3023B = 0;

    /* JADX INFO: renamed from: I, reason: collision with root package name */
    int f3030I = -1;

    /* JADX INFO: renamed from: Q, reason: collision with root package name */
    private int f3038Q = 0;

    /* JADX INFO: renamed from: S, reason: collision with root package name */
    private final View.OnClickListener f3040S = new a();

    public static class RecycleListView extends ListView {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final int f3067b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final int f3068c;

        public RecycleListView(Context context, AttributeSet attributeSet) {
            super(context, attributeSet);
            TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, d.j.f9053c2);
            this.f3068c = typedArrayObtainStyledAttributes.getDimensionPixelOffset(d.j.f9057d2, -1);
            this.f3067b = typedArrayObtainStyledAttributes.getDimensionPixelOffset(d.j.f9061e2, -1);
        }

        public void a(boolean z3, boolean z4) {
            if (z4 && z3) {
                return;
            }
            setPadding(getPaddingLeft(), z3 ? getPaddingTop() : this.f3067b, getPaddingRight(), z4 ? getPaddingBottom() : this.f3068c);
        }
    }

    class a implements View.OnClickListener {
        a() {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            Message message;
            Message message2;
            Message message3;
            AlertController alertController = AlertController.this;
            Message messageObtain = (view != alertController.f3055o || (message3 = alertController.f3057q) == null) ? (view != alertController.f3059s || (message2 = alertController.f3061u) == null) ? (view != alertController.f3063w || (message = alertController.f3065y) == null) ? null : Message.obtain(message) : Message.obtain(message2) : Message.obtain(message3);
            if (messageObtain != null) {
                messageObtain.sendToTarget();
            }
            AlertController alertController2 = AlertController.this;
            alertController2.f3039R.obtainMessage(1, alertController2.f3042b).sendToTarget();
        }
    }

    public static class b {

        /* JADX INFO: renamed from: A, reason: collision with root package name */
        public int f3070A;

        /* JADX INFO: renamed from: B, reason: collision with root package name */
        public int f3071B;

        /* JADX INFO: renamed from: C, reason: collision with root package name */
        public int f3072C;

        /* JADX INFO: renamed from: D, reason: collision with root package name */
        public int f3073D;

        /* JADX INFO: renamed from: F, reason: collision with root package name */
        public boolean[] f3075F;

        /* JADX INFO: renamed from: G, reason: collision with root package name */
        public boolean f3076G;

        /* JADX INFO: renamed from: H, reason: collision with root package name */
        public boolean f3077H;

        /* JADX INFO: renamed from: J, reason: collision with root package name */
        public DialogInterface.OnMultiChoiceClickListener f3079J;

        /* JADX INFO: renamed from: K, reason: collision with root package name */
        public Cursor f3080K;

        /* JADX INFO: renamed from: L, reason: collision with root package name */
        public String f3081L;

        /* JADX INFO: renamed from: M, reason: collision with root package name */
        public String f3082M;

        /* JADX INFO: renamed from: N, reason: collision with root package name */
        public AdapterView.OnItemSelectedListener f3083N;

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public final Context f3085a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        public final LayoutInflater f3086b;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        public Drawable f3088d;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        public CharSequence f3090f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        public View f3091g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        public CharSequence f3092h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        public CharSequence f3093i;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        public Drawable f3094j;

        /* JADX INFO: renamed from: k, reason: collision with root package name */
        public DialogInterface.OnClickListener f3095k;

        /* JADX INFO: renamed from: l, reason: collision with root package name */
        public CharSequence f3096l;

        /* JADX INFO: renamed from: m, reason: collision with root package name */
        public Drawable f3097m;

        /* JADX INFO: renamed from: n, reason: collision with root package name */
        public DialogInterface.OnClickListener f3098n;

        /* JADX INFO: renamed from: o, reason: collision with root package name */
        public CharSequence f3099o;

        /* JADX INFO: renamed from: p, reason: collision with root package name */
        public Drawable f3100p;

        /* JADX INFO: renamed from: q, reason: collision with root package name */
        public DialogInterface.OnClickListener f3101q;

        /* JADX INFO: renamed from: s, reason: collision with root package name */
        public DialogInterface.OnCancelListener f3103s;

        /* JADX INFO: renamed from: t, reason: collision with root package name */
        public DialogInterface.OnDismissListener f3104t;

        /* JADX INFO: renamed from: u, reason: collision with root package name */
        public DialogInterface.OnKeyListener f3105u;

        /* JADX INFO: renamed from: v, reason: collision with root package name */
        public CharSequence[] f3106v;

        /* JADX INFO: renamed from: w, reason: collision with root package name */
        public ListAdapter f3107w;

        /* JADX INFO: renamed from: x, reason: collision with root package name */
        public DialogInterface.OnClickListener f3108x;

        /* JADX INFO: renamed from: y, reason: collision with root package name */
        public int f3109y;

        /* JADX INFO: renamed from: z, reason: collision with root package name */
        public View f3110z;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        public int f3087c = 0;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        public int f3089e = 0;

        /* JADX INFO: renamed from: E, reason: collision with root package name */
        public boolean f3074E = false;

        /* JADX INFO: renamed from: I, reason: collision with root package name */
        public int f3078I = -1;

        /* JADX INFO: renamed from: O, reason: collision with root package name */
        public boolean f3084O = true;

        /* JADX INFO: renamed from: r, reason: collision with root package name */
        public boolean f3102r = true;

        class a extends ArrayAdapter {

            /* JADX INFO: renamed from: a, reason: collision with root package name */
            final /* synthetic */ RecycleListView f3111a;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            a(Context context, int i3, int i4, CharSequence[] charSequenceArr, RecycleListView recycleListView) {
                super(context, i3, i4, charSequenceArr);
                this.f3111a = recycleListView;
            }

            @Override // android.widget.ArrayAdapter, android.widget.Adapter
            public View getView(int i3, View view, ViewGroup viewGroup) {
                View view2 = super.getView(i3, view, viewGroup);
                boolean[] zArr = b.this.f3075F;
                if (zArr != null && zArr[i3]) {
                    this.f3111a.setItemChecked(i3, true);
                }
                return view2;
            }
        }

        /* JADX INFO: renamed from: androidx.appcompat.app.AlertController$b$b, reason: collision with other inner class name */
        class C0048b extends CursorAdapter {

            /* JADX INFO: renamed from: a, reason: collision with root package name */
            private final int f3113a;

            /* JADX INFO: renamed from: b, reason: collision with root package name */
            private final int f3114b;

            /* JADX INFO: renamed from: c, reason: collision with root package name */
            final /* synthetic */ RecycleListView f3115c;

            /* JADX INFO: renamed from: d, reason: collision with root package name */
            final /* synthetic */ AlertController f3116d;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            C0048b(Context context, Cursor cursor, boolean z3, RecycleListView recycleListView, AlertController alertController) {
                super(context, cursor, z3);
                this.f3115c = recycleListView;
                this.f3116d = alertController;
                Cursor cursor2 = getCursor();
                this.f3113a = cursor2.getColumnIndexOrThrow(b.this.f3081L);
                this.f3114b = cursor2.getColumnIndexOrThrow(b.this.f3082M);
            }

            @Override // android.widget.CursorAdapter
            public void bindView(View view, Context context, Cursor cursor) {
                ((CheckedTextView) view.findViewById(R.id.text1)).setText(cursor.getString(this.f3113a));
                this.f3115c.setItemChecked(cursor.getPosition(), cursor.getInt(this.f3114b) == 1);
            }

            @Override // android.widget.CursorAdapter
            public View newView(Context context, Cursor cursor, ViewGroup viewGroup) {
                return b.this.f3086b.inflate(this.f3116d.f3034M, viewGroup, false);
            }
        }

        class c implements AdapterView.OnItemClickListener {

            /* JADX INFO: renamed from: b, reason: collision with root package name */
            final /* synthetic */ AlertController f3118b;

            c(AlertController alertController) {
                this.f3118b = alertController;
            }

            @Override // android.widget.AdapterView.OnItemClickListener
            public void onItemClick(AdapterView adapterView, View view, int i3, long j3) {
                b.this.f3108x.onClick(this.f3118b.f3042b, i3);
                if (b.this.f3077H) {
                    return;
                }
                this.f3118b.f3042b.dismiss();
            }
        }

        class d implements AdapterView.OnItemClickListener {

            /* JADX INFO: renamed from: b, reason: collision with root package name */
            final /* synthetic */ RecycleListView f3120b;

            /* JADX INFO: renamed from: c, reason: collision with root package name */
            final /* synthetic */ AlertController f3121c;

            d(RecycleListView recycleListView, AlertController alertController) {
                this.f3120b = recycleListView;
                this.f3121c = alertController;
            }

            @Override // android.widget.AdapterView.OnItemClickListener
            public void onItemClick(AdapterView adapterView, View view, int i3, long j3) {
                boolean[] zArr = b.this.f3075F;
                if (zArr != null) {
                    zArr[i3] = this.f3120b.isItemChecked(i3);
                }
                b.this.f3079J.onClick(this.f3121c.f3042b, i3, this.f3120b.isItemChecked(i3));
            }
        }

        public b(Context context) {
            this.f3085a = context;
            this.f3086b = (LayoutInflater) context.getSystemService("layout_inflater");
        }

        private void b(AlertController alertController) {
            ListAdapter dVar;
            RecycleListView recycleListView = (RecycleListView) this.f3086b.inflate(alertController.f3033L, (ViewGroup) null);
            if (this.f3076G) {
                dVar = this.f3080K == null ? new a(this.f3085a, alertController.f3034M, R.id.text1, this.f3106v, recycleListView) : new C0048b(this.f3085a, this.f3080K, false, recycleListView, alertController);
            } else {
                int i3 = this.f3077H ? alertController.f3035N : alertController.f3036O;
                if (this.f3080K != null) {
                    dVar = new SimpleCursorAdapter(this.f3085a, i3, this.f3080K, new String[]{this.f3081L}, new int[]{R.id.text1});
                } else {
                    dVar = this.f3107w;
                    if (dVar == null) {
                        dVar = new d(this.f3085a, i3, R.id.text1, this.f3106v);
                    }
                }
            }
            alertController.f3029H = dVar;
            alertController.f3030I = this.f3078I;
            if (this.f3108x != null) {
                recycleListView.setOnItemClickListener(new c(alertController));
            } else if (this.f3079J != null) {
                recycleListView.setOnItemClickListener(new d(recycleListView, alertController));
            }
            AdapterView.OnItemSelectedListener onItemSelectedListener = this.f3083N;
            if (onItemSelectedListener != null) {
                recycleListView.setOnItemSelectedListener(onItemSelectedListener);
            }
            if (this.f3077H) {
                recycleListView.setChoiceMode(1);
            } else if (this.f3076G) {
                recycleListView.setChoiceMode(2);
            }
            alertController.f3047g = recycleListView;
        }

        public void a(AlertController alertController) {
            View view = this.f3091g;
            if (view != null) {
                alertController.k(view);
            } else {
                CharSequence charSequence = this.f3090f;
                if (charSequence != null) {
                    alertController.p(charSequence);
                }
                Drawable drawable = this.f3088d;
                if (drawable != null) {
                    alertController.m(drawable);
                }
                int i3 = this.f3087c;
                if (i3 != 0) {
                    alertController.l(i3);
                }
                int i4 = this.f3089e;
                if (i4 != 0) {
                    alertController.l(alertController.c(i4));
                }
            }
            CharSequence charSequence2 = this.f3092h;
            if (charSequence2 != null) {
                alertController.n(charSequence2);
            }
            CharSequence charSequence3 = this.f3093i;
            if (charSequence3 != null || this.f3094j != null) {
                alertController.j(-1, charSequence3, this.f3095k, null, this.f3094j);
            }
            CharSequence charSequence4 = this.f3096l;
            if (charSequence4 != null || this.f3097m != null) {
                alertController.j(-2, charSequence4, this.f3098n, null, this.f3097m);
            }
            CharSequence charSequence5 = this.f3099o;
            if (charSequence5 != null || this.f3100p != null) {
                alertController.j(-3, charSequence5, this.f3101q, null, this.f3100p);
            }
            if (this.f3106v != null || this.f3080K != null || this.f3107w != null) {
                b(alertController);
            }
            View view2 = this.f3110z;
            if (view2 != null) {
                if (this.f3074E) {
                    alertController.s(view2, this.f3070A, this.f3071B, this.f3072C, this.f3073D);
                    return;
                } else {
                    alertController.r(view2);
                    return;
                }
            }
            int i5 = this.f3109y;
            if (i5 != 0) {
                alertController.q(i5);
            }
        }
    }

    private static final class c extends Handler {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private WeakReference f3123a;

        public c(DialogInterface dialogInterface) {
            this.f3123a = new WeakReference(dialogInterface);
        }

        @Override // android.os.Handler
        public void handleMessage(Message message) {
            int i3 = message.what;
            if (i3 == -3 || i3 == -2 || i3 == -1) {
                ((DialogInterface.OnClickListener) message.obj).onClick((DialogInterface) this.f3123a.get(), message.what);
            } else {
                if (i3 != 1) {
                    return;
                }
                ((DialogInterface) message.obj).dismiss();
            }
        }
    }

    private static class d extends ArrayAdapter {
        public d(Context context, int i3, int i4, CharSequence[] charSequenceArr) {
            super(context, i3, i4, charSequenceArr);
        }

        @Override // android.widget.ArrayAdapter, android.widget.Adapter
        public long getItemId(int i3) {
            return i3;
        }

        @Override // android.widget.BaseAdapter, android.widget.Adapter
        public boolean hasStableIds() {
            return true;
        }
    }

    public AlertController(Context context, r rVar, Window window) {
        this.f3041a = context;
        this.f3042b = rVar;
        this.f3043c = window;
        this.f3039R = new c(rVar);
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(null, d.j.f8965F, AbstractC0502a.f8799k, 0);
        this.f3031J = typedArrayObtainStyledAttributes.getResourceId(d.j.f8969G, 0);
        this.f3032K = typedArrayObtainStyledAttributes.getResourceId(d.j.f8977I, 0);
        this.f3033L = typedArrayObtainStyledAttributes.getResourceId(d.j.f8985K, 0);
        this.f3034M = typedArrayObtainStyledAttributes.getResourceId(d.j.f8989L, 0);
        this.f3035N = typedArrayObtainStyledAttributes.getResourceId(d.j.f8997N, 0);
        this.f3036O = typedArrayObtainStyledAttributes.getResourceId(d.j.f8981J, 0);
        this.f3037P = typedArrayObtainStyledAttributes.getBoolean(d.j.f8993M, true);
        this.f3044d = typedArrayObtainStyledAttributes.getDimensionPixelSize(d.j.f8973H, 0);
        typedArrayObtainStyledAttributes.recycle();
        rVar.l(1);
    }

    static boolean a(View view) {
        if (view.onCheckIsTextEditor()) {
            return true;
        }
        if (!(view instanceof ViewGroup)) {
            return false;
        }
        ViewGroup viewGroup = (ViewGroup) view;
        int childCount = viewGroup.getChildCount();
        while (childCount > 0) {
            childCount--;
            if (a(viewGroup.getChildAt(childCount))) {
                return true;
            }
        }
        return false;
    }

    private void b(Button button) {
        LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) button.getLayoutParams();
        layoutParams.gravity = 1;
        layoutParams.weight = 0.5f;
        button.setLayoutParams(layoutParams);
    }

    private ViewGroup h(View view, View view2) {
        if (view == null) {
            if (view2 instanceof ViewStub) {
                view2 = ((ViewStub) view2).inflate();
            }
            return (ViewGroup) view2;
        }
        if (view2 != null) {
            ViewParent parent = view2.getParent();
            if (parent instanceof ViewGroup) {
                ((ViewGroup) parent).removeView(view2);
            }
        }
        if (view instanceof ViewStub) {
            view = ((ViewStub) view).inflate();
        }
        return (ViewGroup) view;
    }

    private int i() {
        int i3 = this.f3032K;
        return i3 == 0 ? this.f3031J : this.f3038Q == 1 ? i3 : this.f3031J;
    }

    private void o(ViewGroup viewGroup, View view, int i3, int i4) {
        View viewFindViewById = this.f3043c.findViewById(d.f.f8904u);
        View viewFindViewById2 = this.f3043c.findViewById(d.f.f8903t);
        V.k0(view, i3, i4);
        if (viewFindViewById != null) {
            viewGroup.removeView(viewFindViewById);
        }
        if (viewFindViewById2 != null) {
            viewGroup.removeView(viewFindViewById2);
        }
    }

    private void t(ViewGroup viewGroup) {
        int i3;
        Button button = (Button) viewGroup.findViewById(R.id.button1);
        this.f3055o = button;
        button.setOnClickListener(this.f3040S);
        if (TextUtils.isEmpty(this.f3056p) && this.f3058r == null) {
            this.f3055o.setVisibility(8);
            i3 = 0;
        } else {
            this.f3055o.setText(this.f3056p);
            Drawable drawable = this.f3058r;
            if (drawable != null) {
                int i4 = this.f3044d;
                drawable.setBounds(0, 0, i4, i4);
                this.f3055o.setCompoundDrawables(this.f3058r, null, null, null);
            }
            this.f3055o.setVisibility(0);
            i3 = 1;
        }
        Button button2 = (Button) viewGroup.findViewById(R.id.button2);
        this.f3059s = button2;
        button2.setOnClickListener(this.f3040S);
        if (TextUtils.isEmpty(this.f3060t) && this.f3062v == null) {
            this.f3059s.setVisibility(8);
        } else {
            this.f3059s.setText(this.f3060t);
            Drawable drawable2 = this.f3062v;
            if (drawable2 != null) {
                int i5 = this.f3044d;
                drawable2.setBounds(0, 0, i5, i5);
                this.f3059s.setCompoundDrawables(this.f3062v, null, null, null);
            }
            this.f3059s.setVisibility(0);
            i3 |= 2;
        }
        Button button3 = (Button) viewGroup.findViewById(R.id.button3);
        this.f3063w = button3;
        button3.setOnClickListener(this.f3040S);
        if (TextUtils.isEmpty(this.f3064x) && this.f3066z == null) {
            this.f3063w.setVisibility(8);
        } else {
            this.f3063w.setText(this.f3064x);
            Drawable drawable3 = this.f3066z;
            if (drawable3 != null) {
                int i6 = this.f3044d;
                drawable3.setBounds(0, 0, i6, i6);
                this.f3063w.setCompoundDrawables(this.f3066z, null, null, null);
            }
            this.f3063w.setVisibility(0);
            i3 |= 4;
        }
        if (y(this.f3041a)) {
            if (i3 == 1) {
                b(this.f3055o);
            } else if (i3 == 2) {
                b(this.f3059s);
            } else if (i3 == 4) {
                b(this.f3063w);
            }
        }
        if (i3 != 0) {
            return;
        }
        viewGroup.setVisibility(8);
    }

    private void u(ViewGroup viewGroup) {
        NestedScrollView nestedScrollView = (NestedScrollView) this.f3043c.findViewById(d.f.f8905v);
        this.f3022A = nestedScrollView;
        nestedScrollView.setFocusable(false);
        this.f3022A.setNestedScrollingEnabled(false);
        TextView textView = (TextView) viewGroup.findViewById(R.id.message);
        this.f3027F = textView;
        if (textView == null) {
            return;
        }
        CharSequence charSequence = this.f3046f;
        if (charSequence != null) {
            textView.setText(charSequence);
            return;
        }
        textView.setVisibility(8);
        this.f3022A.removeView(this.f3027F);
        if (this.f3047g == null) {
            viewGroup.setVisibility(8);
            return;
        }
        ViewGroup viewGroup2 = (ViewGroup) this.f3022A.getParent();
        int iIndexOfChild = viewGroup2.indexOfChild(this.f3022A);
        viewGroup2.removeViewAt(iIndexOfChild);
        viewGroup2.addView(this.f3047g, iIndexOfChild, new ViewGroup.LayoutParams(-1, -1));
    }

    private void v(ViewGroup viewGroup) {
        View viewInflate = this.f3048h;
        if (viewInflate == null) {
            viewInflate = this.f3049i != 0 ? LayoutInflater.from(this.f3041a).inflate(this.f3049i, viewGroup, false) : null;
        }
        boolean z3 = viewInflate != null;
        if (!z3 || !a(viewInflate)) {
            this.f3043c.setFlags(131072, 131072);
        }
        if (!z3) {
            viewGroup.setVisibility(8);
            return;
        }
        FrameLayout frameLayout = (FrameLayout) this.f3043c.findViewById(d.f.f8897n);
        frameLayout.addView(viewInflate, new ViewGroup.LayoutParams(-1, -1));
        if (this.f3054n) {
            frameLayout.setPadding(this.f3050j, this.f3051k, this.f3052l, this.f3053m);
        }
        if (this.f3047g != null) {
            ((LinearLayout.LayoutParams) ((T.a) viewGroup.getLayoutParams())).weight = 0.0f;
        }
    }

    private void w(ViewGroup viewGroup) {
        if (this.f3028G != null) {
            viewGroup.addView(this.f3028G, 0, new ViewGroup.LayoutParams(-1, -2));
            this.f3043c.findViewById(d.f.f8882E).setVisibility(8);
            return;
        }
        this.f3025D = (ImageView) this.f3043c.findViewById(R.id.icon);
        if (TextUtils.isEmpty(this.f3045e) || !this.f3037P) {
            this.f3043c.findViewById(d.f.f8882E).setVisibility(8);
            this.f3025D.setVisibility(8);
            viewGroup.setVisibility(8);
            return;
        }
        TextView textView = (TextView) this.f3043c.findViewById(d.f.f8893j);
        this.f3026E = textView;
        textView.setText(this.f3045e);
        int i3 = this.f3023B;
        if (i3 != 0) {
            this.f3025D.setImageResource(i3);
            return;
        }
        Drawable drawable = this.f3024C;
        if (drawable != null) {
            this.f3025D.setImageDrawable(drawable);
        } else {
            this.f3026E.setPadding(this.f3025D.getPaddingLeft(), this.f3025D.getPaddingTop(), this.f3025D.getPaddingRight(), this.f3025D.getPaddingBottom());
            this.f3025D.setVisibility(8);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    private void x() {
        View viewFindViewById;
        ListAdapter listAdapter;
        View viewFindViewById2;
        View viewFindViewById3 = this.f3043c.findViewById(d.f.f8902s);
        View viewFindViewById4 = viewFindViewById3.findViewById(d.f.f8883F);
        View viewFindViewById5 = viewFindViewById3.findViewById(d.f.f8896m);
        View viewFindViewById6 = viewFindViewById3.findViewById(d.f.f8894k);
        ViewGroup viewGroup = (ViewGroup) viewFindViewById3.findViewById(d.f.f8898o);
        v(viewGroup);
        View viewFindViewById7 = viewGroup.findViewById(d.f.f8883F);
        View viewFindViewById8 = viewGroup.findViewById(d.f.f8896m);
        View viewFindViewById9 = viewGroup.findViewById(d.f.f8894k);
        ViewGroup viewGroupH = h(viewFindViewById7, viewFindViewById4);
        ViewGroup viewGroupH2 = h(viewFindViewById8, viewFindViewById5);
        ViewGroup viewGroupH3 = h(viewFindViewById9, viewFindViewById6);
        u(viewGroupH2);
        t(viewGroupH3);
        w(viewGroupH);
        boolean z3 = viewGroup.getVisibility() != 8;
        boolean z4 = (viewGroupH == null || viewGroupH.getVisibility() == 8) ? 0 : 1;
        boolean z5 = (viewGroupH3 == null || viewGroupH3.getVisibility() == 8) ? false : true;
        if (!z5 && viewGroupH2 != null && (viewFindViewById2 = viewGroupH2.findViewById(d.f.f8878A)) != null) {
            viewFindViewById2.setVisibility(0);
        }
        if (z4 != 0) {
            NestedScrollView nestedScrollView = this.f3022A;
            if (nestedScrollView != null) {
                nestedScrollView.setClipToPadding(true);
            }
            View viewFindViewById10 = (this.f3046f == null && this.f3047g == null) ? null : viewGroupH.findViewById(d.f.f8881D);
            if (viewFindViewById10 != null) {
                viewFindViewById10.setVisibility(0);
            }
        } else if (viewGroupH2 != null && (viewFindViewById = viewGroupH2.findViewById(d.f.f8879B)) != null) {
            viewFindViewById.setVisibility(0);
        }
        ListView listView = this.f3047g;
        if (listView instanceof RecycleListView) {
            ((RecycleListView) listView).a(z4, z5);
        }
        if (!z3) {
            View view = this.f3047g;
            if (view == null) {
                view = this.f3022A;
            }
            if (view != null) {
                o(viewGroupH2, view, z4 | (z5 ? 2 : 0), 3);
            }
        }
        ListView listView2 = this.f3047g;
        if (listView2 == null || (listAdapter = this.f3029H) == null) {
            return;
        }
        listView2.setAdapter(listAdapter);
        int i3 = this.f3030I;
        if (i3 > -1) {
            listView2.setItemChecked(i3, true);
            listView2.setSelection(i3);
        }
    }

    private static boolean y(Context context) {
        TypedValue typedValue = new TypedValue();
        context.getTheme().resolveAttribute(AbstractC0502a.f8798j, typedValue, true);
        return typedValue.data != 0;
    }

    public int c(int i3) {
        TypedValue typedValue = new TypedValue();
        this.f3041a.getTheme().resolveAttribute(i3, typedValue, true);
        return typedValue.resourceId;
    }

    public ListView d() {
        return this.f3047g;
    }

    public void e() {
        this.f3042b.setContentView(i());
        x();
    }

    public boolean f(int i3, KeyEvent keyEvent) {
        NestedScrollView nestedScrollView = this.f3022A;
        return nestedScrollView != null && nestedScrollView.t(keyEvent);
    }

    public boolean g(int i3, KeyEvent keyEvent) {
        NestedScrollView nestedScrollView = this.f3022A;
        return nestedScrollView != null && nestedScrollView.t(keyEvent);
    }

    public void j(int i3, CharSequence charSequence, DialogInterface.OnClickListener onClickListener, Message message, Drawable drawable) {
        if (message == null && onClickListener != null) {
            message = this.f3039R.obtainMessage(i3, onClickListener);
        }
        if (i3 == -3) {
            this.f3064x = charSequence;
            this.f3065y = message;
            this.f3066z = drawable;
        } else if (i3 == -2) {
            this.f3060t = charSequence;
            this.f3061u = message;
            this.f3062v = drawable;
        } else {
            if (i3 != -1) {
                throw new IllegalArgumentException("Button does not exist");
            }
            this.f3056p = charSequence;
            this.f3057q = message;
            this.f3058r = drawable;
        }
    }

    public void k(View view) {
        this.f3028G = view;
    }

    public void l(int i3) {
        this.f3024C = null;
        this.f3023B = i3;
        ImageView imageView = this.f3025D;
        if (imageView != null) {
            if (i3 == 0) {
                imageView.setVisibility(8);
            } else {
                imageView.setVisibility(0);
                this.f3025D.setImageResource(this.f3023B);
            }
        }
    }

    public void m(Drawable drawable) {
        this.f3024C = drawable;
        this.f3023B = 0;
        ImageView imageView = this.f3025D;
        if (imageView != null) {
            if (drawable == null) {
                imageView.setVisibility(8);
            } else {
                imageView.setVisibility(0);
                this.f3025D.setImageDrawable(drawable);
            }
        }
    }

    public void n(CharSequence charSequence) {
        this.f3046f = charSequence;
        TextView textView = this.f3027F;
        if (textView != null) {
            textView.setText(charSequence);
        }
    }

    public void p(CharSequence charSequence) {
        this.f3045e = charSequence;
        TextView textView = this.f3026E;
        if (textView != null) {
            textView.setText(charSequence);
        }
    }

    public void q(int i3) {
        this.f3048h = null;
        this.f3049i = i3;
        this.f3054n = false;
    }

    public void r(View view) {
        this.f3048h = view;
        this.f3049i = 0;
        this.f3054n = false;
    }

    public void s(View view, int i3, int i4, int i5, int i6) {
        this.f3048h = view;
        this.f3049i = 0;
        this.f3054n = true;
        this.f3050j = i3;
        this.f3051k = i4;
        this.f3052l = i5;
        this.f3053m = i6;
    }
}
