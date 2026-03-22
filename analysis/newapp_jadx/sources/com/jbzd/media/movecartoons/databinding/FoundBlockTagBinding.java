package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FoundBlockTagBinding implements ViewBinding {

    @NonNull
    public final LinearLayout llItem;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerView rvList;

    @NonNull
    public final TextView tvFindDesc;

    @NonNull
    public final TextView tvFindTitle;

    @NonNull
    public final TextView tvMore;

    private FoundBlockTagBinding(@NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull RecyclerView recyclerView, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3) {
        this.rootView = linearLayout;
        this.llItem = linearLayout2;
        this.rvList = recyclerView;
        this.tvFindDesc = textView;
        this.tvFindTitle = textView2;
        this.tvMore = textView3;
    }

    @NonNull
    public static FoundBlockTagBinding bind(@NonNull View view) {
        int i2 = R.id.ll_item;
        LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_item);
        if (linearLayout != null) {
            i2 = R.id.rv_list;
            RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_list);
            if (recyclerView != null) {
                i2 = R.id.tv_findDesc;
                TextView textView = (TextView) view.findViewById(R.id.tv_findDesc);
                if (textView != null) {
                    i2 = R.id.tv_findTitle;
                    TextView textView2 = (TextView) view.findViewById(R.id.tv_findTitle);
                    if (textView2 != null) {
                        i2 = R.id.tv_more;
                        TextView textView3 = (TextView) view.findViewById(R.id.tv_more);
                        if (textView3 != null) {
                            return new FoundBlockTagBinding((LinearLayout) view, linearLayout, recyclerView, textView, textView2, textView3);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static FoundBlockTagBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FoundBlockTagBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.found_block_tag, viewGroup, false);
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
