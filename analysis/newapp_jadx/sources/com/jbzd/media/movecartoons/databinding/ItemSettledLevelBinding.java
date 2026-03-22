package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemSettledLevelBinding implements ViewBinding {

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvDesc;

    @NonNull
    public final TextView tvName;

    @NonNull
    public final TextView tvPrePrice;

    private ItemSettledLevelBinding(@NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3) {
        this.rootView = linearLayout;
        this.tvDesc = textView;
        this.tvName = textView2;
        this.tvPrePrice = textView3;
    }

    @NonNull
    public static ItemSettledLevelBinding bind(@NonNull View view) {
        int i2 = R.id.tv_desc;
        TextView textView = (TextView) view.findViewById(R.id.tv_desc);
        if (textView != null) {
            i2 = R.id.tv_name;
            TextView textView2 = (TextView) view.findViewById(R.id.tv_name);
            if (textView2 != null) {
                i2 = R.id.tv_prePrice;
                TextView textView3 = (TextView) view.findViewById(R.id.tv_prePrice);
                if (textView3 != null) {
                    return new ItemSettledLevelBinding((LinearLayout) view, textView, textView2, textView3);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemSettledLevelBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemSettledLevelBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_settled_level, viewGroup, false);
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
