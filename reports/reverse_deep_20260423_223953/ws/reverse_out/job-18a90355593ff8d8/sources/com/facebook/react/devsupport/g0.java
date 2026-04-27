package com.facebook.react.devsupport;

import B2.B;
import android.content.Context;
import android.net.Uri;
import android.os.AsyncTask;
import android.util.Pair;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ListAdapter;
import android.widget.ListView;
import android.widget.TextView;
import c1.AbstractC0339k;
import c1.AbstractC0341m;
import j1.i;
import java.util.concurrent.Executor;
import kotlin.jvm.internal.DefaultConstructorMarker;
import org.json.JSONObject;

/* JADX INFO: loaded from: classes.dex */
public final class g0 extends LinearLayout implements AdapterView.OnItemClickListener {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final j1.e f6830b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private ListView f6831c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final i.a f6832d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final View.OnClickListener f6833e;

    private static final class a extends AsyncTask {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        public static final C0105a f6834b = new C0105a(null);

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private static final B2.x f6835c = B2.x.f437g.a("application/json; charset=utf-8");

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final j1.e f6836a;

        /* JADX INFO: renamed from: com.facebook.react.devsupport.g0$a$a, reason: collision with other inner class name */
        public static final class C0105a {
            public /* synthetic */ C0105a(DefaultConstructorMarker defaultConstructorMarker) {
                this();
            }

            /* JADX INFO: Access modifiers changed from: private */
            public final JSONObject b(j1.j jVar) {
                return new JSONObject(i2.D.h(h2.n.a("file", jVar.getFile()), h2.n.a("methodName", jVar.d()), h2.n.a("lineNumber", Integer.valueOf(jVar.c())), h2.n.a("column", Integer.valueOf(jVar.getColumn()))));
            }

            private C0105a() {
            }
        }

        public a(j1.e eVar) {
            t2.j.f(eVar, "devSupportManager");
            this.f6836a = eVar;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public Void doInBackground(j1.j... jVarArr) {
            String string;
            B2.z zVar;
            int i3;
            t2.j.f(jVarArr, "stackFrames");
            try {
                string = Uri.parse(this.f6836a.E()).buildUpon().path("/open-stack-frame").query(null).build().toString();
                t2.j.e(string, "toString(...)");
                zVar = new B2.z();
            } catch (Exception e3) {
                Y.a.n("ReactNative", "Could not open stack frame", e3);
            }
            for (j1.j jVar : jVarArr) {
                C0105a c0105a = f6834b;
                if (jVar == null) {
                    throw new IllegalStateException("Required value was null.");
                }
                String string2 = c0105a.b(jVar).toString();
                t2.j.e(string2, "toString(...)");
                zVar.a(new B.a().m(string).h(B2.C.f97a.b(f6835c, string2)).b()).b();
                return null;
            }
            return null;
        }
    }

    private static final class b extends BaseAdapter {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        public static final a f6837c = new a(null);

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final String f6838a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final j1.j[] f6839b;

        public static final class a {
            public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
                this();
            }

            private a() {
            }
        }

        /* JADX INFO: renamed from: com.facebook.react.devsupport.g0$b$b, reason: collision with other inner class name */
        private static final class C0106b {

            /* JADX INFO: renamed from: a, reason: collision with root package name */
            private final TextView f6840a;

            /* JADX INFO: renamed from: b, reason: collision with root package name */
            private final TextView f6841b;

            public C0106b(View view) {
                t2.j.f(view, "v");
                View viewFindViewById = view.findViewById(AbstractC0339k.f5598v);
                t2.j.e(viewFindViewById, "findViewById(...)");
                this.f6840a = (TextView) viewFindViewById;
                View viewFindViewById2 = view.findViewById(AbstractC0339k.f5597u);
                t2.j.e(viewFindViewById2, "findViewById(...)");
                this.f6841b = (TextView) viewFindViewById2;
            }

            public final TextView a() {
                return this.f6841b;
            }

            public final TextView b() {
                return this.f6840a;
            }
        }

        public b(String str, j1.j[] jVarArr) {
            t2.j.f(str, "title");
            t2.j.f(jVarArr, "stack");
            this.f6838a = str;
            this.f6839b = jVarArr;
        }

        @Override // android.widget.BaseAdapter, android.widget.ListAdapter
        public boolean areAllItemsEnabled() {
            return false;
        }

        @Override // android.widget.Adapter
        public int getCount() {
            return this.f6839b.length + 1;
        }

        @Override // android.widget.Adapter
        public Object getItem(int i3) {
            return i3 == 0 ? this.f6838a : this.f6839b[i3 - 1];
        }

        @Override // android.widget.Adapter
        public long getItemId(int i3) {
            return i3;
        }

        @Override // android.widget.BaseAdapter, android.widget.Adapter
        public int getItemViewType(int i3) {
            return i3 == 0 ? 0 : 1;
        }

        @Override // android.widget.Adapter
        public View getView(int i3, View view, ViewGroup viewGroup) {
            TextView textView;
            t2.j.f(viewGroup, "parent");
            if (i3 == 0) {
                if (view != null) {
                    textView = (TextView) view;
                } else {
                    View viewInflate = LayoutInflater.from(viewGroup.getContext()).inflate(AbstractC0341m.f5609f, viewGroup, false);
                    t2.j.d(viewInflate, "null cannot be cast to non-null type android.widget.TextView");
                    textView = (TextView) viewInflate;
                }
                textView.setText(new z2.f("\\x1b\\[[0-9;]*m").b(this.f6838a, ""));
                return textView;
            }
            if (view == null) {
                view = LayoutInflater.from(viewGroup.getContext()).inflate(AbstractC0341m.f5608e, viewGroup, false);
                t2.j.c(view);
                view.setTag(new C0106b(view));
            }
            j1.j jVar = this.f6839b[i3 - 1];
            Object tag = view.getTag();
            t2.j.d(tag, "null cannot be cast to non-null type com.facebook.react.devsupport.RedBoxContentView.StackAdapter.FrameViewHolder");
            C0106b c0106b = (C0106b) tag;
            c0106b.b().setText(jVar.d());
            c0106b.a().setText(l0.c(jVar));
            c0106b.b().setTextColor(jVar.b() ? -5592406 : -1);
            c0106b.a().setTextColor(jVar.b() ? -8355712 : -5000269);
            return view;
        }

        @Override // android.widget.BaseAdapter, android.widget.Adapter
        public int getViewTypeCount() {
            return 2;
        }

        @Override // android.widget.BaseAdapter, android.widget.ListAdapter
        public boolean isEnabled(int i3) {
            return i3 > 0;
        }
    }

    public static final class c implements i.a {
        c() {
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g0(Context context, j1.e eVar, j1.i iVar) {
        super(context);
        t2.j.f(eVar, "devSupportManager");
        this.f6830b = eVar;
        this.f6832d = new c();
        this.f6833e = new View.OnClickListener() { // from class: com.facebook.react.devsupport.d0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                g0.h(this.f6820b, view);
            }
        };
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void e(g0 g0Var, View view) {
        g0Var.f6830b.r();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void f(g0 g0Var, View view) {
        g0Var.f6830b.o();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void h(g0 g0Var, View view) {
        g0Var.getClass();
    }

    public final void d() {
        LayoutInflater.from(getContext()).inflate(AbstractC0341m.f5610g, this);
        ListView listView = (ListView) findViewById(AbstractC0339k.f5601y);
        listView.setOnItemClickListener(this);
        this.f6831c = listView;
        ((Button) findViewById(AbstractC0339k.f5600x)).setOnClickListener(new View.OnClickListener() { // from class: com.facebook.react.devsupport.e0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                g0.e(this.f6825b, view);
            }
        });
        ((Button) findViewById(AbstractC0339k.f5599w)).setOnClickListener(new View.OnClickListener() { // from class: com.facebook.react.devsupport.f0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                g0.f(this.f6827b, view);
            }
        });
    }

    public final void g() {
        String strK = this.f6830b.k();
        j1.j[] jVarArrV = this.f6830b.v();
        if (jVarArrV == null) {
            jVarArrV = new j1.j[0];
        }
        if (this.f6830b.B() == null) {
            throw new IllegalStateException("Required value was null.");
        }
        Pair pairX = this.f6830b.x(Pair.create(strK, jVarArrV));
        if (pairX == null) {
            throw new IllegalStateException("Required value was null.");
        }
        Object obj = pairX.first;
        t2.j.e(obj, "first");
        Object obj2 = pairX.second;
        t2.j.e(obj2, "second");
        i((String) obj, (j1.j[]) obj2);
        this.f6830b.s();
    }

    public final void i(String str, j1.j[] jVarArr) {
        t2.j.f(str, "title");
        t2.j.f(jVarArr, "stack");
        ListView listView = this.f6831c;
        if (listView == null) {
            t2.j.s("stackView");
            listView = null;
        }
        listView.setAdapter((ListAdapter) new b(str, jVarArr));
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // android.widget.AdapterView.OnItemClickListener
    public void onItemClick(AdapterView adapterView, View view, int i3, long j3) {
        t2.j.f(view, "view");
        a aVar = new a(this.f6830b);
        Executor executor = AsyncTask.THREAD_POOL_EXECUTOR;
        j1.j[] jVarArr = new j1.j[1];
        ListView listView = this.f6831c;
        if (listView == null) {
            t2.j.s("stackView");
            listView = null;
        }
        Object item = listView.getAdapter().getItem(i3);
        t2.j.d(item, "null cannot be cast to non-null type com.facebook.react.devsupport.interfaces.StackFrame");
        jVarArr[0] = item;
        aVar.executeOnExecutor(executor, jVarArr);
    }
}
