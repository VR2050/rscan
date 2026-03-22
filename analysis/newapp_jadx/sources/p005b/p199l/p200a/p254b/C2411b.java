package p005b.p199l.p200a.p254b;

import android.view.View;
import com.google.android.flexbox.FlexItem;
import java.util.ArrayList;
import java.util.List;

/* renamed from: b.l.a.b.b */
/* loaded from: classes.dex */
public class C2411b {

    /* renamed from: e */
    public int f6422e;

    /* renamed from: f */
    public int f6423f;

    /* renamed from: g */
    public int f6424g;

    /* renamed from: h */
    public int f6425h;

    /* renamed from: i */
    public int f6426i;

    /* renamed from: j */
    public float f6427j;

    /* renamed from: k */
    public float f6428k;

    /* renamed from: l */
    public int f6429l;

    /* renamed from: m */
    public int f6430m;

    /* renamed from: o */
    public int f6432o;

    /* renamed from: p */
    public int f6433p;

    /* renamed from: q */
    public boolean f6434q;

    /* renamed from: r */
    public boolean f6435r;

    /* renamed from: a */
    public int f6418a = Integer.MAX_VALUE;

    /* renamed from: b */
    public int f6419b = Integer.MAX_VALUE;

    /* renamed from: c */
    public int f6420c = Integer.MIN_VALUE;

    /* renamed from: d */
    public int f6421d = Integer.MIN_VALUE;

    /* renamed from: n */
    public List<Integer> f6431n = new ArrayList();

    /* renamed from: a */
    public int m2720a() {
        return this.f6425h - this.f6426i;
    }

    /* renamed from: b */
    public void m2721b(View view, int i2, int i3, int i4, int i5) {
        FlexItem flexItem = (FlexItem) view.getLayoutParams();
        this.f6418a = Math.min(this.f6418a, (view.getLeft() - flexItem.mo4139i()) - i2);
        this.f6419b = Math.min(this.f6419b, (view.getTop() - flexItem.mo4140j()) - i3);
        this.f6420c = Math.max(this.f6420c, flexItem.mo4144p() + view.getRight() + i4);
        this.f6421d = Math.max(this.f6421d, flexItem.mo4138h() + view.getBottom() + i5);
    }
}
