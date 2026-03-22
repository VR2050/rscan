package p448i.p452b.p453a.p454h;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import androidx.recyclerview.widget.RecyclerView;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import me.jingbin.library.adapter.BaseByRecyclerViewAdapter;

/* renamed from: i.b.a.h.a */
/* loaded from: classes3.dex */
public class C4360a {

    /* renamed from: a */
    public final RecyclerView f11257a;

    /* renamed from: b */
    public RecyclerView.ViewHolder f11258b;

    /* renamed from: c */
    public View f11259c;

    /* renamed from: d */
    public final boolean f11260d;

    /* renamed from: e */
    public List<Integer> f11261e;

    /* renamed from: f */
    public int f11262f;

    /* renamed from: g */
    public boolean f11263g;

    /* renamed from: h */
    public int f11264h = -1;

    /* renamed from: i */
    public float f11265i = -1.0f;

    /* renamed from: j */
    public int f11266j = -1;

    /* renamed from: k */
    public final ViewTreeObserver.OnGlobalLayoutListener f11267k = new a();

    /* renamed from: i.b.a.h.a$a */
    public class a implements ViewTreeObserver.OnGlobalLayoutListener {
        public a() {
        }

        @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
        public void onGlobalLayout() {
            int visibility = C4360a.this.f11257a.getVisibility();
            View view = C4360a.this.f11259c;
            if (view != null) {
                view.setVisibility(visibility);
            }
        }
    }

    /* renamed from: i.b.a.h.a$b */
    public class b implements Runnable {
        public b() {
        }

        @Override // java.lang.Runnable
        public void run() {
            View view;
            C4360a c4360a = C4360a.this;
            if (c4360a.f11265i == -1.0f || (view = c4360a.f11259c) == null) {
                return;
            }
            if ((c4360a.f11262f == 1 && view.getTranslationY() == 0.0f) || (c4360a.f11262f == 0 && c4360a.f11259c.getTranslationX() == 0.0f)) {
                if (c4360a.f11259c.getTag() != null) {
                    return;
                }
                c4360a.f11259c.setTag(Boolean.TRUE);
                c4360a.f11259c.animate().z(c4360a.f11265i);
                return;
            }
            if (c4360a.f11259c.getTag() != null) {
                c4360a.f11259c.setTag(null);
                c4360a.f11259c.animate().z(0.0f);
            }
        }
    }

    public C4360a(RecyclerView recyclerView) {
        this.f11257a = recyclerView;
        this.f11260d = recyclerView.getPaddingLeft() > 0 || recyclerView.getPaddingRight() > 0 || recyclerView.getPaddingTop() > 0;
    }

    /* renamed from: a */
    public static int m4929a(C4360a c4360a) {
        View view = c4360a.f11259c;
        if (view == null) {
            return 0;
        }
        return c4360a.f11262f == 1 ? view.getHeight() : view.getWidth();
    }

    /* renamed from: b */
    public final void m4930b(Map<Integer, View> map) {
        boolean z;
        float f2;
        View view = this.f11259c;
        if (view == null) {
            return;
        }
        if (view.getHeight() == 0) {
            View view2 = this.f11259c;
            if (view2 == null) {
                return;
            }
            view2.getViewTreeObserver().addOnGlobalLayoutListener(new ViewTreeObserverOnGlobalLayoutListenerC4362c(this, view2, map));
            return;
        }
        Iterator<Map.Entry<Integer, View>> it = map.entrySet().iterator();
        while (true) {
            if (!it.hasNext()) {
                break;
            }
            Map.Entry<Integer, View> next = it.next();
            if (next.getKey().intValue() > this.f11264h) {
                View value = next.getValue();
                if (!(this.f11262f != 1 ? value.getX() < ((float) this.f11259c.getWidth()) : value.getY() < ((float) this.f11259c.getHeight()))) {
                    f2 = -1.0f;
                } else if (this.f11262f == 1) {
                    f2 = -(this.f11259c.getHeight() - value.getY());
                    this.f11259c.setTranslationY(f2);
                } else {
                    f2 = -(this.f11259c.getWidth() - value.getX());
                    this.f11259c.setTranslationX(f2);
                }
                if (f2 != -1.0f) {
                    z = false;
                }
            }
        }
        z = true;
        if (z) {
            if (this.f11262f == 1) {
                this.f11259c.setTranslationY(0.0f);
            } else {
                this.f11259c.setTranslationX(0.0f);
            }
        }
        this.f11259c.setVisibility(0);
    }

    /* renamed from: c */
    public void m4931c() {
        this.f11257a.getViewTreeObserver().removeOnGlobalLayoutListener(this.f11267k);
    }

    /* renamed from: d */
    public final void m4932d() {
        if (this.f11259c != null) {
            m4933e().removeView(this.f11259c);
            m4931c();
            this.f11259c = null;
            this.f11258b = null;
        }
    }

    /* renamed from: e */
    public final ViewGroup m4933e() {
        return (ViewGroup) this.f11257a.getParent();
    }

    /* renamed from: f */
    public final int m4934f() {
        try {
            return ((BaseByRecyclerViewAdapter) this.f11257a.getAdapter()).m5633a();
        } catch (Exception e2) {
            e2.printStackTrace();
            return 0;
        }
    }

    /* renamed from: g */
    public final boolean m4935g(View view) {
        if (view != null) {
            if (this.f11262f == 1) {
                if (view.getY() > 0.0f) {
                    return true;
                }
            } else if (view.getX() > 0.0f) {
                return true;
            }
        }
        return false;
    }

    /* renamed from: h */
    public void m4936h(int i2, Map<Integer, View> map, C4364e c4364e, boolean z) {
        int i3;
        int indexOf;
        if (z) {
            i3 = -1;
        } else {
            View view = map.get(Integer.valueOf(i2));
            if (!(view != null && (this.f11262f != 1 ? view.getX() > 0.0f : view.getY() > 0.0f)) || (indexOf = this.f11261e.indexOf(Integer.valueOf(i2))) <= 0) {
                int i4 = -1;
                for (Integer num : this.f11261e) {
                    if (num.intValue() > i2) {
                        break;
                    } else {
                        i4 = num.intValue();
                    }
                }
                i3 = i4;
            } else {
                i3 = this.f11261e.get(indexOf - 1).intValue();
            }
        }
        View view2 = map.get(Integer.valueOf(i3));
        if (i3 != this.f11264h) {
            if (i3 == -1 || (this.f11260d && m4935g(view2))) {
                this.f11263g = true;
                m4933e().post(new RunnableC4363d(this, this.f11264h));
                this.f11264h = -1;
            } else {
                this.f11264h = i3;
                int m4934f = i3 - m4934f();
                if (c4364e.f11280c != c4364e.f11278a.getAdapter().getItemViewType(m4934f)) {
                    c4364e.f11280c = c4364e.f11278a.getAdapter().getItemViewType(m4934f);
                    c4364e.f11279b = c4364e.f11278a.getAdapter().createViewHolder((ViewGroup) c4364e.f11278a.getParent(), c4364e.f11280c);
                }
                RecyclerView.ViewHolder viewHolder = c4364e.f11279b;
                int m4934f2 = i3 - m4934f();
                if (this.f11258b == viewHolder) {
                    this.f11257a.getAdapter().onBindViewHolder(this.f11258b, m4934f2);
                    this.f11258b.itemView.requestLayout();
                    View view3 = this.f11259c;
                    if (view3 != null) {
                        view3.getViewTreeObserver().addOnGlobalLayoutListener(new ViewTreeObserverOnGlobalLayoutListenerC4361b(this, view3));
                    }
                    this.f11263g = false;
                } else {
                    m4932d();
                    this.f11258b = viewHolder;
                    this.f11257a.getAdapter().onBindViewHolder(this.f11258b, m4934f2);
                    View view4 = this.f11258b.itemView;
                    this.f11259c = view4;
                    Context context = view4.getContext();
                    int i5 = this.f11266j;
                    if (i5 != -1 && this.f11265i == -1.0f) {
                        this.f11265i = i5 * context.getResources().getDisplayMetrics().density;
                    }
                    this.f11259c.setVisibility(4);
                    this.f11257a.getViewTreeObserver().addOnGlobalLayoutListener(this.f11267k);
                    m4933e().addView(this.f11259c);
                    if (this.f11260d) {
                        ((ViewGroup.MarginLayoutParams) this.f11259c.getLayoutParams()).setMargins(this.f11262f == 1 ? this.f11257a.getPaddingLeft() : 0, this.f11262f == 1 ? 0 : this.f11257a.getPaddingTop(), this.f11262f == 1 ? this.f11257a.getPaddingRight() : 0, 0);
                    }
                    this.f11263g = false;
                }
            }
        } else if (this.f11260d && m4935g(view2)) {
            m4932d();
            this.f11264h = -1;
        }
        m4930b(map);
        this.f11257a.post(new b());
    }
}
