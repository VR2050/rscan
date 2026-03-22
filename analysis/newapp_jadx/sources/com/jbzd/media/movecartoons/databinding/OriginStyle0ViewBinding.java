package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.MyGridView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class OriginStyle0ViewBinding implements ViewBinding {

    @NonNull
    public final MyGridView lvItems;

    @NonNull
    private final LinearLayout rootView;

    private OriginStyle0ViewBinding(@NonNull LinearLayout linearLayout, @NonNull MyGridView myGridView) {
        this.rootView = linearLayout;
        this.lvItems = myGridView;
    }

    @NonNull
    public static OriginStyle0ViewBinding bind(@NonNull View view) {
        MyGridView myGridView = (MyGridView) view.findViewById(R.id.lv_items);
        if (myGridView != null) {
            return new OriginStyle0ViewBinding((LinearLayout) view, myGridView);
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.lv_items)));
    }

    @NonNull
    public static OriginStyle0ViewBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static OriginStyle0ViewBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.origin_style0_view, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public LinearLayout getRoot() {
        return this.rootView;
    }
}
