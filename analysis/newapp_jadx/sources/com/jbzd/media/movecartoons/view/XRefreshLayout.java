package com.jbzd.media.movecartoons.view;

import android.content.Context;
import android.util.AttributeSet;
import com.scwang.smartrefresh.layout.SmartRefreshLayout;
import com.scwang.smartrefresh.layout.footer.ClassicsFooter;
import com.scwang.smartrefresh.layout.header.ClassicsHeader;
import p005b.p340x.p354b.p355a.p357c.EnumC2903b;

/* loaded from: classes2.dex */
public class XRefreshLayout extends SmartRefreshLayout {
    private Context context;

    public XRefreshLayout(Context context) {
        this(context, null);
    }

    private void setDef() {
        setRefreshHeader(new ClassicsHeader(this.context));
        setRefreshFooter(new ClassicsFooter(this.context));
    }

    @Override // com.scwang.smartrefresh.layout.SmartRefreshLayout
    public void notifyStateChanged(EnumC2903b enumC2903b) {
        super.notifyStateChanged(enumC2903b);
    }

    public XRefreshLayout(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public XRefreshLayout(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet);
        this.context = context;
        setDef();
    }
}
