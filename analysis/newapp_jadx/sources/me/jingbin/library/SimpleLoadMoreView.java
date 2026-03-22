package me.jingbin.library;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import p448i.p452b.p453a.InterfaceC4354b;

/* loaded from: classes3.dex */
public class SimpleLoadMoreView extends LinearLayout implements InterfaceC4354b {

    /* renamed from: c */
    public View f12700c;

    /* renamed from: e */
    public boolean f12701e;

    /* renamed from: f */
    public TextView f12702f;

    /* renamed from: g */
    public TextView f12703g;

    /* renamed from: h */
    public LinearLayout f12704h;

    /* renamed from: i */
    public int f12705i;

    public SimpleLoadMoreView(Context context) {
        super(context);
        this.f12701e = false;
        this.f12705i = 1;
        LayoutInflater.from(context).inflate(R$layout.simple_by_load_more_view, this);
        this.f12700c = findViewById(R$id.view_bottom);
        this.f12704h = (LinearLayout) findViewById(R$id.ll_more_loading);
        this.f12702f = (TextView) findViewById(R$id.tv_no_more);
        this.f12703g = (TextView) findViewById(R$id.tv_more_failed);
        setLayoutParams(new LinearLayout.LayoutParams(-1, -2));
    }

    public View getFailureView() {
        return this.f12703g;
    }

    @Override // p448i.p452b.p453a.InterfaceC4354b
    public int getState() {
        return this.f12705i;
    }

    @Override // p448i.p452b.p453a.InterfaceC4354b
    public void setLoadingMoreBottomHeight(float f2) {
        if (f2 > 0.0f) {
            this.f12700c.setLayoutParams(new LinearLayout.LayoutParams(-1, (int) ((f2 * getResources().getDisplayMetrics().density) + 0.5f)));
            this.f12701e = true;
        }
    }

    @Override // p448i.p452b.p453a.InterfaceC4354b
    public void setState(int i2) {
        setVisibility(0);
        if (i2 == 0) {
            this.f12704h.setVisibility(0);
            this.f12702f.setVisibility(8);
            this.f12703g.setVisibility(8);
        } else if (i2 == 1) {
            this.f12704h.setVisibility(0);
            this.f12702f.setVisibility(8);
            this.f12703g.setVisibility(8);
            setVisibility(8);
        } else if (i2 == 2) {
            this.f12702f.setVisibility(0);
            this.f12704h.setVisibility(8);
            this.f12703g.setVisibility(8);
        } else if (i2 == 3) {
            this.f12703g.setVisibility(0);
            this.f12704h.setVisibility(8);
            this.f12702f.setVisibility(8);
        }
        if (this.f12701e) {
            this.f12700c.setVisibility(0);
        } else {
            this.f12700c.setVisibility(8);
        }
        this.f12705i = i2;
    }
}
