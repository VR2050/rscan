package im.uwrkaxlmjj.ui.hui.login;

import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import butterknife.Unbinder;
import butterknife.internal.DebouncingOnClickListener;
import butterknife.internal.Utils;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.RadialProgressView;
import im.uwrkaxlmjj.ui.hviews.MryEditText;
import im.uwrkaxlmjj.ui.hviews.MryRoundButton;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ChangePersonalInformationActivity_ViewBinding implements Unbinder {
    private ChangePersonalInformationActivity target;
    private View view7f09009c;
    private View view7f0900e0;
    private View view7f0900e5;
    private View view7f0900e9;
    private View view7f0903fc;
    private View view7f0904c3;

    public ChangePersonalInformationActivity_ViewBinding(final ChangePersonalInformationActivity target, View source) {
        this.target = target;
        View view = Utils.findRequiredView(source, R.attr.containerAvatar, "field 'containerAvatar' and method 'onClick'");
        target.containerAvatar = view;
        this.view7f0900e0 = view;
        view.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.ChangePersonalInformationActivity_ViewBinding.1
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onClick(p0);
            }
        });
        target.containerCamera = Utils.findRequiredView(source, R.attr.containerCamera, "field 'containerCamera'");
        target.ivCamera = (ImageView) Utils.findRequiredViewAsType(source, R.attr.ivCamera, "field 'ivCamera'", ImageView.class);
        target.tvCamera = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvCamera, "field 'tvCamera'", MryTextView.class);
        target.ivAvatar = (BackupImageView) Utils.findRequiredViewAsType(source, R.attr.ivAvatar, "field 'ivAvatar'", BackupImageView.class);
        target.ivAvatarProgress = (RadialProgressView) Utils.findRequiredViewAsType(source, R.attr.ivAvatarProgress, "field 'ivAvatarProgress'", RadialProgressView.class);
        target.etNickName = (MryEditText) Utils.findRequiredViewAsType(source, R.attr.etNickName, "field 'etNickName'", MryEditText.class);
        target.selectDataOfBirthParent = Utils.findRequiredView(source, R.attr.selectDataOfBirthParent, "field 'selectDataOfBirthParent'");
        target.containerGenderSelect = Utils.findRequiredView(source, R.attr.containerGenderSelect, "field 'containerGenderSelect'");
        View view2 = Utils.findRequiredView(source, R.attr.selectSexParent, "field 'selectSexParent' and method 'onClick'");
        target.selectSexParent = view2;
        this.view7f0903fc = view2;
        view2.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.ChangePersonalInformationActivity_ViewBinding.2
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onClick(p0);
            }
        });
        View view3 = Utils.findRequiredView(source, R.attr.containerMale, "field 'containerMale' and method 'onClick'");
        target.containerMale = view3;
        this.view7f0900e9 = view3;
        view3.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.ChangePersonalInformationActivity_ViewBinding.3
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onClick(p0);
            }
        });
        target.ivMale = (ImageView) Utils.findRequiredViewAsType(source, R.attr.ivMale, "field 'ivMale'", ImageView.class);
        target.tvMale = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvMale, "field 'tvMale'", MryTextView.class);
        View view4 = Utils.findRequiredView(source, R.attr.containerFemale, "field 'containerFemale' and method 'onClick'");
        target.containerFemale = view4;
        this.view7f0900e5 = view4;
        view4.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.ChangePersonalInformationActivity_ViewBinding.4
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onClick(p0);
            }
        });
        target.ivFemale = (ImageView) Utils.findRequiredViewAsType(source, R.attr.ivFemale, "field 'ivFemale'", ImageView.class);
        target.tvSelectSex = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvSelectSex, "field 'tvSelectSex'", MryTextView.class);
        target.tvFemale = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvFemale, "field 'tvFemale'", MryTextView.class);
        target.tvSelectDateOfBirth = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvSelectDateOfBirth, "field 'tvSelectDateOfBirth'", MryTextView.class);
        View view5 = Utils.findRequiredView(source, R.attr.tvDate, "field 'tvDate' and method 'onClick'");
        target.tvDate = (TextView) Utils.castView(view5, R.attr.tvDate, "field 'tvDate'", TextView.class);
        this.view7f0904c3 = view5;
        view5.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.ChangePersonalInformationActivity_ViewBinding.5
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onClick(p0);
            }
        });
        target.ivMore = (ImageView) Utils.findRequiredViewAsType(source, R.attr.ivMore, "field 'ivMore'", ImageView.class);
        View view6 = Utils.findRequiredView(source, R.attr.btnDone, "field 'btnDone' and method 'onClick'");
        target.btnDone = (MryRoundButton) Utils.castView(view6, R.attr.btnDone, "field 'btnDone'", MryRoundButton.class);
        this.view7f09009c = view6;
        view6.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.ChangePersonalInformationActivity_ViewBinding.6
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onClick(p0);
            }
        });
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        ChangePersonalInformationActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.containerAvatar = null;
        target.containerCamera = null;
        target.ivCamera = null;
        target.tvCamera = null;
        target.ivAvatar = null;
        target.ivAvatarProgress = null;
        target.etNickName = null;
        target.selectDataOfBirthParent = null;
        target.containerGenderSelect = null;
        target.selectSexParent = null;
        target.containerMale = null;
        target.ivMale = null;
        target.tvMale = null;
        target.containerFemale = null;
        target.ivFemale = null;
        target.tvSelectSex = null;
        target.tvFemale = null;
        target.tvSelectDateOfBirth = null;
        target.tvDate = null;
        target.ivMore = null;
        target.btnDone = null;
        this.view7f0900e0.setOnClickListener(null);
        this.view7f0900e0 = null;
        this.view7f0903fc.setOnClickListener(null);
        this.view7f0903fc = null;
        this.view7f0900e9.setOnClickListener(null);
        this.view7f0900e9 = null;
        this.view7f0900e5.setOnClickListener(null);
        this.view7f0900e5 = null;
        this.view7f0904c3.setOnClickListener(null);
        this.view7f0904c3 = null;
        this.view7f09009c.setOnClickListener(null);
        this.view7f09009c = null;
    }
}
