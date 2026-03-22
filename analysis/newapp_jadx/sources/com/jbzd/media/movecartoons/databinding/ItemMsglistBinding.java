package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemMsglistBinding implements ViewBinding {

    @NonNull
    public final CircleImageView civHead;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvContentPre;

    @NonNull
    public final TextView tvName;

    @NonNull
    public final TextView tvTime;

    private ItemMsglistBinding(@NonNull LinearLayout linearLayout, @NonNull CircleImageView circleImageView, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3) {
        this.rootView = linearLayout;
        this.civHead = circleImageView;
        this.tvContentPre = textView;
        this.tvName = textView2;
        this.tvTime = textView3;
    }

    @NonNull
    public static ItemMsglistBinding bind(@NonNull View view) {
        int i2 = R.id.civ_head;
        CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.civ_head);
        if (circleImageView != null) {
            i2 = R.id.tv_contentPre;
            TextView textView = (TextView) view.findViewById(R.id.tv_contentPre);
            if (textView != null) {
                i2 = R.id.tv_name;
                TextView textView2 = (TextView) view.findViewById(R.id.tv_name);
                if (textView2 != null) {
                    i2 = R.id.tv_time;
                    TextView textView3 = (TextView) view.findViewById(R.id.tv_time);
                    if (textView3 != null) {
                        return new ItemMsglistBinding((LinearLayout) view, circleImageView, textView, textView2, textView3);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemMsglistBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemMsglistBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_msglist, viewGroup, false);
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
