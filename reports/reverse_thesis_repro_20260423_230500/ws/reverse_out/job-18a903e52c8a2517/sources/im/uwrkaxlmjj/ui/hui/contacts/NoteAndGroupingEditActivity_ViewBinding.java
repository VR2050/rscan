package im.uwrkaxlmjj.ui.hui.contacts;

import android.view.View;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import butterknife.Unbinder;
import butterknife.internal.DebouncingOnClickListener;
import butterknife.internal.Utils;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class NoteAndGroupingEditActivity_ViewBinding implements Unbinder {
    private NoteAndGroupingEditActivity target;
    private View view7f0901d6;
    private View view7f0904f7;

    public NoteAndGroupingEditActivity_ViewBinding(final NoteAndGroupingEditActivity target, View source) {
        this.target = target;
        target.tvGroupDescView = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvGroupDescView, "field 'tvGroupDescView'", TextView.class);
        View view = Utils.findRequiredView(source, R.attr.tvGroupingSettingView, "field 'tvGroupingSettingView' and method 'onViewClicked'");
        target.tvGroupingSettingView = (TextView) Utils.castView(view, R.attr.tvGroupingSettingView, "field 'tvGroupingSettingView'", TextView.class);
        this.view7f0904f7 = view;
        view.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.NoteAndGroupingEditActivity_ViewBinding.1
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked(p0);
            }
        });
        target.tvNoteDescView = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvNoteDescView, "field 'tvNoteDescView'", TextView.class);
        target.etNoteEditView = (EditText) Utils.findRequiredViewAsType(source, R.attr.etNoteEditView, "field 'etNoteEditView'", EditText.class);
        View view2 = Utils.findRequiredView(source, R.attr.ivClearNoteView, "field 'ivClearNoteView' and method 'onViewClicked'");
        target.ivClearNoteView = (ImageView) Utils.castView(view2, R.attr.ivClearNoteView, "field 'ivClearNoteView'", ImageView.class);
        this.view7f0901d6 = view2;
        view2.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.NoteAndGroupingEditActivity_ViewBinding.2
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked(p0);
            }
        });
        target.flNoteSettingLayout = (FrameLayout) Utils.findRequiredViewAsType(source, R.attr.flNoteSettingLayout, "field 'flNoteSettingLayout'", FrameLayout.class);
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        NoteAndGroupingEditActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.tvGroupDescView = null;
        target.tvGroupingSettingView = null;
        target.tvNoteDescView = null;
        target.etNoteEditView = null;
        target.ivClearNoteView = null;
        target.flNoteSettingLayout = null;
        this.view7f0904f7.setOnClickListener(null);
        this.view7f0904f7 = null;
        this.view7f0901d6.setOnClickListener(null);
        this.view7f0901d6 = null;
    }
}
