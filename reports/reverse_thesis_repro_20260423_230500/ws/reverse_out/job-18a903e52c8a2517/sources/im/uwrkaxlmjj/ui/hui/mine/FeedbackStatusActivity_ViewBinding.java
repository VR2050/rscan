package im.uwrkaxlmjj.ui.hui.mine;

import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import butterknife.Unbinder;
import butterknife.internal.DebouncingOnClickListener;
import butterknife.internal.Utils;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FeedbackStatusActivity_ViewBinding implements Unbinder {
    private FeedbackStatusActivity target;
    private View view7f0900a0;

    public FeedbackStatusActivity_ViewBinding(final FeedbackStatusActivity target, View source) {
        this.target = target;
        target.ivFeedStatusImg = (ImageView) Utils.findRequiredViewAsType(source, R.attr.ivFeedStatusImg, "field 'ivFeedStatusImg'", ImageView.class);
        target.mryFeedStatusText = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.mryFeedStatusText, "field 'mryFeedStatusText'", MryTextView.class);
        target.mryFeedDescText = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.mryFeedDescText, "field 'mryFeedDescText'", MryTextView.class);
        View view = Utils.findRequiredView(source, R.attr.btnFinish, "field 'btnFinish' and method 'onViewClicked'");
        target.btnFinish = (Button) Utils.castView(view, R.attr.btnFinish, "field 'btnFinish'", Button.class);
        this.view7f0900a0 = view;
        view.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.FeedbackStatusActivity_ViewBinding.1
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked();
            }
        });
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        FeedbackStatusActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.ivFeedStatusImg = null;
        target.mryFeedStatusText = null;
        target.mryFeedDescText = null;
        target.btnFinish = null;
        this.view7f0900a0.setOnClickListener(null);
        this.view7f0900a0 = null;
    }
}
