package im.uwrkaxlmjj.ui.hviews.pop;

import android.content.Context;
import android.view.View;

/* JADX INFO: loaded from: classes5.dex */
public class EasyPopup extends BasePopup<EasyPopup> {
    private OnViewListener mOnViewListener;

    public interface OnViewListener {
        void initViews(View view, EasyPopup easyPopup);
    }

    public static EasyPopup create() {
        return new EasyPopup();
    }

    public static EasyPopup create(Context context) {
        return new EasyPopup(context);
    }

    public EasyPopup() {
    }

    public EasyPopup(Context context) {
        setContext(context);
    }

    @Override // im.uwrkaxlmjj.ui.hviews.pop.BasePopup
    protected void initAttributes() {
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // im.uwrkaxlmjj.ui.hviews.pop.BasePopup
    public void initViews(View view, EasyPopup popup) {
        OnViewListener onViewListener = this.mOnViewListener;
        if (onViewListener != null) {
            onViewListener.initViews(view, popup);
        }
    }

    public EasyPopup setOnViewListener(OnViewListener listener) {
        this.mOnViewListener = listener;
        return this;
    }
}
