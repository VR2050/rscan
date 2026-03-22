package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogInputCommentBinding implements ViewBinding {

    @NonNull
    public final EditText edInputComment;

    @NonNull
    public final ImageTextView itvConfirmPost;

    @NonNull
    public final ImageTextView itvFavorite;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final LinearLayout titleLayout;

    private DialogInputCommentBinding(@NonNull LinearLayout linearLayout, @NonNull EditText editText, @NonNull ImageTextView imageTextView, @NonNull ImageTextView imageTextView2, @NonNull LinearLayout linearLayout2) {
        this.rootView = linearLayout;
        this.edInputComment = editText;
        this.itvConfirmPost = imageTextView;
        this.itvFavorite = imageTextView2;
        this.titleLayout = linearLayout2;
    }

    @NonNull
    public static DialogInputCommentBinding bind(@NonNull View view) {
        int i2 = R.id.ed_input_comment;
        EditText editText = (EditText) view.findViewById(R.id.ed_input_comment);
        if (editText != null) {
            i2 = R.id.itv_confirm_post;
            ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_confirm_post);
            if (imageTextView != null) {
                i2 = R.id.itv_favorite;
                ImageTextView imageTextView2 = (ImageTextView) view.findViewById(R.id.itv_favorite);
                if (imageTextView2 != null) {
                    LinearLayout linearLayout = (LinearLayout) view;
                    return new DialogInputCommentBinding(linearLayout, editText, imageTextView, imageTextView2, linearLayout);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogInputCommentBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogInputCommentBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_input_comment, viewGroup, false);
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
