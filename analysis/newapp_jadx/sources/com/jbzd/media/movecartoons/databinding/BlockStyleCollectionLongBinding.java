package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class BlockStyleCollectionLongBinding implements ViewBinding {

    @NonNull
    public final ImageView ivOption;

    @NonNull
    public final LinearLayout llModule;

    @NonNull
    public final LinearLayout llTitleLayout;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerView rvList;

    @NonNull
    public final TextView tvDesc;

    @NonNull
    public final TextView tvTitle;

    @NonNull
    public final View vListDivider;

    private BlockStyleCollectionLongBinding(@NonNull LinearLayout linearLayout, @NonNull ImageView imageView, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull RecyclerView recyclerView, @NonNull TextView textView, @NonNull TextView textView2, @NonNull View view) {
        this.rootView = linearLayout;
        this.ivOption = imageView;
        this.llModule = linearLayout2;
        this.llTitleLayout = linearLayout3;
        this.rvList = recyclerView;
        this.tvDesc = textView;
        this.tvTitle = textView2;
        this.vListDivider = view;
    }

    @NonNull
    public static BlockStyleCollectionLongBinding bind(@NonNull View view) {
        int i2 = R.id.iv_option;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_option);
        if (imageView != null) {
            i2 = R.id.ll_module;
            LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_module);
            if (linearLayout != null) {
                i2 = R.id.ll_titleLayout;
                LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_titleLayout);
                if (linearLayout2 != null) {
                    i2 = R.id.rv_list;
                    RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_list);
                    if (recyclerView != null) {
                        i2 = R.id.tv_desc;
                        TextView textView = (TextView) view.findViewById(R.id.tv_desc);
                        if (textView != null) {
                            i2 = R.id.tv_title;
                            TextView textView2 = (TextView) view.findViewById(R.id.tv_title);
                            if (textView2 != null) {
                                i2 = R.id.v_listDivider;
                                View findViewById = view.findViewById(R.id.v_listDivider);
                                if (findViewById != null) {
                                    return new BlockStyleCollectionLongBinding((LinearLayout) view, imageView, linearLayout, linearLayout2, recyclerView, textView, textView2, findViewById);
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static BlockStyleCollectionLongBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static BlockStyleCollectionLongBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.block_style_collection_long, viewGroup, false);
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
