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
public final class ItemShareHeadBinding implements ViewBinding {

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvShareitemCode;

    @NonNull
    public final TextView tvShareitemName;

    @NonNull
    public final TextView tvShareitemTime;

    private ItemShareHeadBinding(@NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3) {
        this.rootView = linearLayout;
        this.tvShareitemCode = textView;
        this.tvShareitemName = textView2;
        this.tvShareitemTime = textView3;
    }

    @NonNull
    public static ItemShareHeadBinding bind(@NonNull View view) {
        int i2 = R.id.tv_shareitem_code;
        TextView textView = (TextView) view.findViewById(R.id.tv_shareitem_code);
        if (textView != null) {
            i2 = R.id.tv_shareitem_name;
            TextView textView2 = (TextView) view.findViewById(R.id.tv_shareitem_name);
            if (textView2 != null) {
                i2 = R.id.tv_shareitem_time;
                TextView textView3 = (TextView) view.findViewById(R.id.tv_shareitem_time);
                if (textView3 != null) {
                    return new ItemShareHeadBinding((LinearLayout) view, textView, textView2, textView3);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemShareHeadBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemShareHeadBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_share_head, viewGroup, false);
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
