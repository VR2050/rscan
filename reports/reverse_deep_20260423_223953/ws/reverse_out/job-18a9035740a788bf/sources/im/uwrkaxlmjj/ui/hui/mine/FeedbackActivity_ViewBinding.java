package im.uwrkaxlmjj.ui.hui.mine;

import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import butterknife.Unbinder;
import butterknife.internal.DebouncingOnClickListener;
import butterknife.internal.Utils;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FeedbackActivity_ViewBinding implements Unbinder {
    private FeedbackActivity target;
    private View view7f09009f;

    public FeedbackActivity_ViewBinding(final FeedbackActivity target, View source) {
        this.target = target;
        target.mryFeedTitle = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.mryFeedTitle, "field 'mryFeedTitle'", MryTextView.class);
        target.etFeedDescText = (EditText) Utils.findRequiredViewAsType(source, R.attr.etFeedDescText, "field 'etFeedDescText'", EditText.class);
        View view = Utils.findRequiredView(source, R.attr.btnFeedSubmit, "field 'btnFeedSubmit' and method 'onViewClicked'");
        target.btnFeedSubmit = (Button) Utils.castView(view, R.attr.btnFeedSubmit, "field 'btnFeedSubmit'", Button.class);
        this.view7f09009f = view;
        view.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.FeedbackActivity_ViewBinding.1
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked();
            }
        });
        target.tvFeedPromt = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvFeedPromt, "field 'tvFeedPromt'", TextView.class);
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        FeedbackActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.mryFeedTitle = null;
        target.etFeedDescText = null;
        target.btnFeedSubmit = null;
        target.tvFeedPromt = null;
        this.view7f09009f.setOnClickListener(null);
        this.view7f09009f = null;
    }
}
