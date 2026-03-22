package com.scwang.smart.refresh.header;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.ColorInt;
import androidx.annotation.NonNull;
import androidx.fragment.app.FragmentActivity;
import androidx.fragment.app.FragmentManager;
import com.scwang.smart.refresh.classics.ClassicsAbstract;
import com.scwang.smart.refresh.header.classics.R$id;
import com.scwang.smart.refresh.header.classics.R$layout;
import com.scwang.smart.refresh.header.classics.R$string;
import com.scwang.smart.refresh.header.classics.R$styleable;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import p005b.p340x.p341a.p342a.C2866b;
import p005b.p340x.p341a.p343b.p344a.C2867a;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2874d;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2876f;
import p005b.p340x.p341a.p343b.p347c.p349b.C2879c;
import p005b.p340x.p341a.p343b.p347c.p349b.EnumC2878b;
import p005b.p340x.p341a.p343b.p347c.p352e.InterpolatorC2889b;

/* loaded from: classes2.dex */
public class ClassicsHeader extends ClassicsAbstract<ClassicsHeader> implements InterfaceC2874d {

    /* renamed from: A */
    public String f10476A;

    /* renamed from: B */
    public String f10477B;

    /* renamed from: C */
    public String f10478C;

    /* renamed from: D */
    public String f10479D;

    /* renamed from: E */
    public String f10480E;

    /* renamed from: F */
    public String f10481F;

    /* renamed from: G */
    public String f10482G;

    /* renamed from: t */
    public String f10483t;

    /* renamed from: u */
    public Date f10484u;

    /* renamed from: v */
    public TextView f10485v;

    /* renamed from: w */
    public SharedPreferences f10486w;

    /* renamed from: x */
    public DateFormat f10487x;

    /* renamed from: y */
    public boolean f10488y;

    /* renamed from: z */
    public String f10489z;

    public ClassicsHeader(Context context) {
        this(context, null);
    }

    @Override // com.scwang.smart.refresh.classics.ClassicsAbstract, com.scwang.smart.refresh.layout.simple.SimpleComponent, p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2871a
    /* renamed from: f */
    public int mo3318f(@NonNull InterfaceC2876f interfaceC2876f, boolean z) {
        if (z) {
            this.f10455g.setText(this.f10479D);
            if (this.f10484u != null) {
                m4600l(new Date());
            }
        } else {
            this.f10455g.setText(this.f10480E);
        }
        return super.mo3318f(interfaceC2876f, z);
    }

    @Override // com.scwang.smart.refresh.layout.simple.SimpleComponent, p005b.p340x.p341a.p343b.p347c.p350c.InterfaceC2885f
    /* renamed from: h */
    public void mo3328h(@NonNull InterfaceC2876f interfaceC2876f, @NonNull EnumC2878b enumC2878b, @NonNull EnumC2878b enumC2878b2) {
        ImageView imageView = this.f10456h;
        TextView textView = this.f10485v;
        int ordinal = enumC2878b2.ordinal();
        if (ordinal == 0) {
            textView.setVisibility(this.f10488y ? 0 : 8);
        } else if (ordinal != 1) {
            if (ordinal == 5) {
                this.f10455g.setText(this.f10478C);
                imageView.animate().rotation(180.0f);
                return;
            }
            if (ordinal == 7) {
                this.f10455g.setText(this.f10482G);
                imageView.animate().rotation(0.0f);
                return;
            } else if (ordinal == 9 || ordinal == 11) {
                this.f10455g.setText(this.f10476A);
                imageView.setVisibility(8);
                return;
            } else {
                if (ordinal != 12) {
                    return;
                }
                imageView.setVisibility(8);
                textView.setVisibility(this.f10488y ? 4 : 8);
                this.f10455g.setText(this.f10477B);
                return;
            }
        }
        this.f10455g.setText(this.f10489z);
        imageView.setVisibility(0);
        imageView.animate().rotation(0.0f);
    }

    @Override // com.scwang.smart.refresh.classics.ClassicsAbstract
    /* renamed from: j */
    public ClassicsHeader mo4598j(@ColorInt int i2) {
        this.f10485v.setTextColor((16777215 & i2) | (-872415232));
        super.mo4598j(i2);
        return this;
    }

    /* renamed from: l */
    public ClassicsHeader m4600l(Date date) {
        this.f10484u = date;
        this.f10485v.setText(this.f10487x.format(date));
        if (this.f10486w != null && !isInEditMode()) {
            this.f10486w.edit().putLong(this.f10483t, date.getTime()).apply();
        }
        return this;
    }

    public ClassicsHeader(Context context, AttributeSet attributeSet) {
        super(context, attributeSet, 0);
        FragmentManager supportFragmentManager;
        this.f10483t = "LAST_UPDATE_TIME";
        this.f10488y = true;
        View.inflate(context, R$layout.srl_classics_header, this);
        ImageView imageView = (ImageView) findViewById(R$id.srl_classics_arrow);
        this.f10456h = imageView;
        TextView textView = (TextView) findViewById(R$id.srl_classics_update);
        this.f10485v = textView;
        ImageView imageView2 = (ImageView) findViewById(R$id.srl_classics_progress);
        this.f10457i = imageView2;
        this.f10455g = (TextView) findViewById(R$id.srl_classics_title);
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.ClassicsHeader);
        RelativeLayout.LayoutParams layoutParams = (RelativeLayout.LayoutParams) imageView.getLayoutParams();
        RelativeLayout.LayoutParams layoutParams2 = (RelativeLayout.LayoutParams) imageView2.getLayoutParams();
        new LinearLayout.LayoutParams(-2, -2).topMargin = obtainStyledAttributes.getDimensionPixelSize(R$styleable.ClassicsHeader_srlTextTimeMarginTop, InterpolatorC2889b.m3333c(0.0f));
        int dimensionPixelSize = obtainStyledAttributes.getDimensionPixelSize(R$styleable.ClassicsHeader_srlDrawableMarginRight, InterpolatorC2889b.m3333c(20.0f));
        layoutParams2.rightMargin = dimensionPixelSize;
        layoutParams.rightMargin = dimensionPixelSize;
        int i2 = R$styleable.ClassicsHeader_srlDrawableArrowSize;
        layoutParams.width = obtainStyledAttributes.getLayoutDimension(i2, layoutParams.width);
        layoutParams.height = obtainStyledAttributes.getLayoutDimension(i2, layoutParams.height);
        int i3 = R$styleable.ClassicsHeader_srlDrawableProgressSize;
        layoutParams2.width = obtainStyledAttributes.getLayoutDimension(i3, layoutParams2.width);
        layoutParams2.height = obtainStyledAttributes.getLayoutDimension(i3, layoutParams2.height);
        int i4 = R$styleable.ClassicsHeader_srlDrawableSize;
        layoutParams.width = obtainStyledAttributes.getLayoutDimension(i4, layoutParams.width);
        layoutParams.height = obtainStyledAttributes.getLayoutDimension(i4, layoutParams.height);
        layoutParams2.width = obtainStyledAttributes.getLayoutDimension(i4, layoutParams2.width);
        layoutParams2.height = obtainStyledAttributes.getLayoutDimension(i4, layoutParams2.height);
        this.f10464p = obtainStyledAttributes.getInt(R$styleable.ClassicsHeader_srlFinishDuration, this.f10464p);
        this.f10488y = obtainStyledAttributes.getBoolean(R$styleable.ClassicsHeader_srlEnableLastTime, this.f10488y);
        this.f10627e = C2879c.f7892f[obtainStyledAttributes.getInt(R$styleable.ClassicsHeader_srlClassicsSpinnerStyle, this.f10627e.f7893g)];
        int i5 = R$styleable.ClassicsHeader_srlDrawableArrow;
        if (obtainStyledAttributes.hasValue(i5)) {
            this.f10456h.setImageDrawable(obtainStyledAttributes.getDrawable(i5));
        } else if (this.f10456h.getDrawable() == null) {
            C2867a c2867a = new C2867a();
            this.f10459k = c2867a;
            c2867a.f7802c.setColor(-10066330);
            this.f10456h.setImageDrawable(this.f10459k);
        }
        int i6 = R$styleable.ClassicsHeader_srlDrawableProgress;
        if (obtainStyledAttributes.hasValue(i6)) {
            this.f10457i.setImageDrawable(obtainStyledAttributes.getDrawable(i6));
        } else if (this.f10457i.getDrawable() == null) {
            C2866b c2866b = new C2866b();
            this.f10460l = c2866b;
            c2866b.f7802c.setColor(-10066330);
            this.f10457i.setImageDrawable(this.f10460l);
        }
        if (obtainStyledAttributes.hasValue(R$styleable.ClassicsHeader_srlTextSizeTitle)) {
            this.f10455g.setTextSize(0, obtainStyledAttributes.getDimensionPixelSize(r4, InterpolatorC2889b.m3333c(16.0f)));
        }
        if (obtainStyledAttributes.hasValue(R$styleable.ClassicsHeader_srlTextSizeTime)) {
            this.f10485v.setTextSize(0, obtainStyledAttributes.getDimensionPixelSize(r4, InterpolatorC2889b.m3333c(12.0f)));
        }
        int i7 = R$styleable.ClassicsHeader_srlPrimaryColor;
        if (obtainStyledAttributes.hasValue(i7)) {
            m4599k(obtainStyledAttributes.getColor(i7, 0));
        }
        int i8 = R$styleable.ClassicsHeader_srlAccentColor;
        if (obtainStyledAttributes.hasValue(i8)) {
            int color = obtainStyledAttributes.getColor(i8, 0);
            this.f10485v.setTextColor((16777215 & color) | (-872415232));
            super.mo4598j(color);
        }
        int i9 = R$styleable.ClassicsHeader_srlTextPulling;
        if (obtainStyledAttributes.hasValue(i9)) {
            this.f10489z = obtainStyledAttributes.getString(i9);
        } else {
            this.f10489z = context.getString(R$string.srl_header_pulling);
        }
        int i10 = R$styleable.ClassicsHeader_srlTextLoading;
        if (obtainStyledAttributes.hasValue(i10)) {
            this.f10477B = obtainStyledAttributes.getString(i10);
        } else {
            this.f10477B = context.getString(R$string.srl_header_loading);
        }
        int i11 = R$styleable.ClassicsHeader_srlTextRelease;
        if (obtainStyledAttributes.hasValue(i11)) {
            this.f10478C = obtainStyledAttributes.getString(i11);
        } else {
            this.f10478C = context.getString(R$string.srl_header_release);
        }
        int i12 = R$styleable.ClassicsHeader_srlTextFinish;
        if (obtainStyledAttributes.hasValue(i12)) {
            this.f10479D = obtainStyledAttributes.getString(i12);
        } else {
            this.f10479D = context.getString(R$string.srl_header_finish);
        }
        int i13 = R$styleable.ClassicsHeader_srlTextFailed;
        if (obtainStyledAttributes.hasValue(i13)) {
            this.f10480E = obtainStyledAttributes.getString(i13);
        } else {
            this.f10480E = context.getString(R$string.srl_header_failed);
        }
        int i14 = R$styleable.ClassicsHeader_srlTextSecondary;
        if (obtainStyledAttributes.hasValue(i14)) {
            this.f10482G = obtainStyledAttributes.getString(i14);
        } else {
            this.f10482G = context.getString(R$string.srl_header_secondary);
        }
        int i15 = R$styleable.ClassicsHeader_srlTextRefreshing;
        if (obtainStyledAttributes.hasValue(i15)) {
            this.f10476A = obtainStyledAttributes.getString(i15);
        } else {
            this.f10476A = context.getString(R$string.srl_header_refreshing);
        }
        int i16 = R$styleable.ClassicsHeader_srlTextUpdate;
        if (obtainStyledAttributes.hasValue(i16)) {
            this.f10481F = obtainStyledAttributes.getString(i16);
        } else {
            this.f10481F = context.getString(R$string.srl_header_update);
        }
        this.f10487x = new SimpleDateFormat(this.f10481F, Locale.getDefault());
        obtainStyledAttributes.recycle();
        imageView2.animate().setInterpolator(null);
        textView.setVisibility(this.f10488y ? 0 : 8);
        this.f10455g.setText(isInEditMode() ? this.f10476A : this.f10489z);
        if (isInEditMode()) {
            imageView.setVisibility(8);
        } else {
            imageView2.setVisibility(8);
        }
        try {
            if ((context instanceof FragmentActivity) && (supportFragmentManager = ((FragmentActivity) context).getSupportFragmentManager()) != null && supportFragmentManager.getFragments().size() > 0) {
                m4600l(new Date());
                return;
            }
        } catch (Throwable th) {
            th.printStackTrace();
        }
        this.f10483t += context.getClass().getName();
        this.f10486w = context.getSharedPreferences("ClassicsHeader", 0);
        m4600l(new Date(this.f10486w.getLong(this.f10483t, System.currentTimeMillis())));
    }
}
