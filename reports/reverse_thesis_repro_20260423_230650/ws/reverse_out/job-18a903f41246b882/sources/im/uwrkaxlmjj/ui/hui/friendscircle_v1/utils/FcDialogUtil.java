package im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils;

import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Color;
import androidx.core.content.ContextCompat;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.dialogs.FcDialog;
import im.uwrkaxlmjj.ui.fragments.BaseFmts;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcFragment;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FcDialogUtil {
    public static void chooseIsSetOtherFcItemPrivacyDialog(Object fragment, FcDialog.OnConfirmClickListener OnConfirmClickListener, DialogInterface.OnDismissListener onDismissListener) {
        String title = LocaleController.getString("provicy_other_fc_item", R.string.provicy_other_fc_item);
        String content = LocaleController.getString("provicy_other_fc_item_sure", R.string.provicy_other_fc_item_sure);
        setDialog(fragment, title, content, LocaleController.getString("OK", R.string.OK), LocaleController.getString("Cancel", R.string.Cancel), OnConfirmClickListener, onDismissListener);
    }

    public static void chooseIsDeleteMineItemDialog(Object fragment, FcDialog.OnConfirmClickListener OnConfirmClickListener, DialogInterface.OnDismissListener onDismissListener) {
        String title = LocaleController.getString("fc_delete_mine", R.string.fc_delete_mine);
        String content = LocaleController.getString("fc_delete_mine_sure", R.string.fc_delete_mine_sure);
        setDialog(fragment, title, content, LocaleController.getString("OK", R.string.OK), LocaleController.getString("Cancel", R.string.Cancel), OnConfirmClickListener, onDismissListener);
    }

    public static void showDeleteAlbumItemDialog(Object fragment, int urlType, boolean hasSameGroup, FcDialog.OnConfirmClickListener OnConfirmClickListener, DialogInterface.OnDismissListener onDismissListener) {
        String content;
        String deleteTips;
        String deleteTips2 = LocaleController.getString("Delete", R.string.Delete);
        if (urlType == 2) {
            String content2 = LocaleController.getString("fc_delete_fc_video", R.string.fc_delete_fc_video);
            content = content2;
            deleteTips = deleteTips2;
        } else if (hasSameGroup) {
            String content3 = LocaleController.getString("fc_delete_fc_multiple_pictures", R.string.fc_delete_fc_multiple_pictures);
            content = content3;
            deleteTips = LocaleController.getString("DeleteAll", R.string.DeleteAll);
        } else {
            String content4 = LocaleController.getString("fc_delete_fc_pictures", R.string.fc_delete_fc_pictures);
            content = content4;
            deleteTips = deleteTips2;
        }
        if (!(fragment instanceof BaseFragment)) {
            if (fragment instanceof BaseFmts) {
                BaseFmts fmt = (BaseFmts) fragment;
                setDialog(fmt, "", content, deleteTips, LocaleController.getString("Cancel", R.string.Cancel), Color.parseColor("#F74C31"), Color.parseColor("#3BBCFF"), OnConfirmClickListener, onDismissListener);
                return;
            }
            if (fragment instanceof BaseFcFragment) {
                BaseFcFragment fmt2 = (BaseFcFragment) fragment;
                setDialog(fmt2, "", content, LocaleController.getString("OK", R.string.OK), LocaleController.getString("Cancel", R.string.Cancel), OnConfirmClickListener, onDismissListener);
                return;
            }
            return;
        }
        BaseFragment fmt3 = (BaseFragment) fragment;
        setDialog(fmt3, "", content, deleteTips, LocaleController.getString("Cancel", R.string.Cancel), Color.parseColor("#F74C31"), Color.parseColor("#3BBCFF"), OnConfirmClickListener, onDismissListener);
    }

    public static void chooseIsDeleteCommentDialog(Object fragment, FcDialog.OnConfirmClickListener OnConfirmClickListener, DialogInterface.OnDismissListener onDismissListener) {
        String title = LocaleController.getString("fc_delete_comment", R.string.fc_delete_comment);
        String content = LocaleController.getString("fc_delete_comment_sure", R.string.fc_delete_comment_sure);
        setDialog(fragment, title, content, LocaleController.getString("OK", R.string.OK), LocaleController.getString("Cancel", R.string.Cancel), OnConfirmClickListener, onDismissListener);
    }

    public static void chooseCancelFollowedDialog(Object fragment, boolean isFemale, FcDialog.OnConfirmClickListener OnConfirmClickListener, DialogInterface.OnDismissListener onDismissListener) {
        String tips;
        String title = LocaleController.getString("fc_cancel_followed", R.string.fc_cancel_followed);
        if (isFemale) {
            tips = LocaleController.getString("fc_cancel_followed_her_tips", R.string.fc_cancel_followed_her_tips);
        } else {
            tips = LocaleController.getString("fc_cancel_followed_him_tips", R.string.fc_cancel_followed_him_tips);
        }
        setDialog(fragment, title, tips, LocaleController.getString("OK", R.string.OK), LocaleController.getString("Cancel", R.string.Cancel), OnConfirmClickListener, onDismissListener);
    }

    public static void choosePrivacyAllFcDialog(Object fragment, FcDialog.OnConfirmClickListener OnConfirmClickListener, DialogInterface.OnDismissListener onDismissListener) {
        String title = LocaleController.getString("fc_no_look_theyfc", R.string.fc_no_look_theyfc);
        String content = LocaleController.getString("fc_no_look_theyfc_sure", R.string.fc_no_look_theyfc_sure);
        setDialog(fragment, title, content, LocaleController.getString("OK", R.string.OK), LocaleController.getString("Cancel", R.string.Cancel), OnConfirmClickListener, onDismissListener);
    }

    public static void isDeleteThisPic(Object fragment, FcDialog.OnConfirmClickListener OnConfirmClickListener, DialogInterface.OnDismissListener onDismissListener) {
        String title = LocaleController.getString("image_select_tip", R.string.image_select_tip);
        String content = LocaleController.getString("friendscircle_publish_delete_photo", R.string.friendscircle_publish_delete_photo);
        if (fragment instanceof BaseFragment) {
            BaseFragment fmt = (BaseFragment) fragment;
            setDialog(fmt, title, content, LocaleController.getString("OK", R.string.OK), LocaleController.getString("Cancel", R.string.Cancel), OnConfirmClickListener, onDismissListener);
        } else if (fragment instanceof BaseFmts) {
            BaseFmts fmt2 = (BaseFmts) fragment;
            setDialog(fmt2, title, content, LocaleController.getString("OK", R.string.OK), LocaleController.getString("Cancel", R.string.Cancel), OnConfirmClickListener, onDismissListener);
        } else if (fragment instanceof BaseFcFragment) {
            BaseFcFragment fmt3 = (BaseFcFragment) fragment;
            setDialog(fmt3, title, content, LocaleController.getString("OK", R.string.OK), LocaleController.getString("Cancel", R.string.Cancel), OnConfirmClickListener, onDismissListener);
        }
    }

    public static void isDeleteThisVideo(Object fragment, FcDialog.OnConfirmClickListener OnConfirmClickListener, DialogInterface.OnDismissListener onDismissListener) {
        String title = LocaleController.getString("image_select_tip", R.string.image_select_tip);
        String content = LocaleController.getString("friendscircle_publish_delete_video", R.string.friendscircle_publish_delete_video);
        setDialog(fragment, title, content, LocaleController.getString("OK", R.string.OK), LocaleController.getString("Cancel", R.string.Cancel), OnConfirmClickListener, onDismissListener);
    }

    public static void exitPublish(Object fragment, FcDialog.OnConfirmClickListener OnConfirmClickListener, DialogInterface.OnDismissListener onDismissListener) {
        String title = LocaleController.getString("image_select_tip", R.string.image_select_tip);
        String content = LocaleController.getString("friendscircle_publish_exit_tip", R.string.friendscircle_publish_exit_tip);
        int btnColor = ContextCompat.getColor(ApplicationLoader.applicationContext, R.color.color_FF2ECEFD);
        setDialog(fragment, title, content, LocaleController.getString(R.string.PublishDoSave), LocaleController.getString(R.string.PublishDoNotSave), btnColor, btnColor, OnConfirmClickListener, onDismissListener);
    }

    public static void publishError(Object fragment, FcDialog.OnConfirmClickListener OnConfirmClickListener, DialogInterface.OnDismissListener onDismissListener) {
        String title = LocaleController.getString("image_select_tip", R.string.image_select_tip);
        String content = LocaleController.getString("friendscircle_publish_fail", R.string.friendscircle_publish_fail);
        setDialog(fragment, title, content, LocaleController.getString("OK", R.string.OK), null, OnConfirmClickListener, onDismissListener);
    }

    public static void publishServerBusyError(Object fragment, FcDialog.OnConfirmClickListener OnConfirmClickListener, DialogInterface.OnDismissListener onDismissListener) {
        String title = LocaleController.getString("image_select_tip", R.string.image_select_tip);
        String content = LocaleController.getString("friendscircle_publish_server_busy", R.string.friendscircle_publish_server_busy);
        if (fragment instanceof BaseFragment) {
            BaseFragment fmt = (BaseFragment) fragment;
            setDialog(fmt, title, content, LocaleController.getString("OK", R.string.OK), null, OnConfirmClickListener, onDismissListener);
        } else if (fragment instanceof BaseFmts) {
            BaseFmts fmt2 = (BaseFmts) fragment;
            setDialog(fmt2, title, content, LocaleController.getString("OK", R.string.OK), null, OnConfirmClickListener, onDismissListener);
        }
    }

    public static void setDialog(Object fragment, String title, String content, String confirmText, String cancelText, FcDialog.OnConfirmClickListener onConfirmClickListener, DialogInterface.OnDismissListener onDismissListener) {
        setDialog(fragment, title, content, confirmText, cancelText, 0, 0, onConfirmClickListener, onDismissListener);
    }

    public static void setDialog(Object fragment, String title, String content, String confirmText, String cancelText, int confirmTextColor, int cancleTextColor, FcDialog.OnConfirmClickListener onConfirmClickListener, DialogInterface.OnDismissListener onDismissListener) {
        Context context = null;
        if (fragment instanceof BaseFragment) {
            BaseFragment fmt = (BaseFragment) fragment;
            context = fmt.getParentActivity();
        } else if (fragment instanceof BaseFmts) {
            BaseFmts fmt2 = (BaseFmts) fragment;
            context = fmt2.getParentActivity();
        } else if (fragment instanceof BaseFcFragment) {
            BaseFcFragment fmt3 = (BaseFcFragment) fragment;
            context = fmt3.getParentActivity();
        }
        if (context == null) {
            return;
        }
        FcDialog dialog = new FcDialog(context);
        dialog.setCancelable(false);
        dialog.setTitle(title);
        dialog.setContent(content);
        dialog.setConfirmButtonColor(confirmTextColor);
        dialog.setCancelButtonColor(cancleTextColor);
        dialog.setOnConfirmClickListener(confirmText, onConfirmClickListener);
        dialog.setOnCancelClickListener(cancelText, null);
        if (fragment instanceof BaseFragment) {
            BaseFragment fmt4 = (BaseFragment) fragment;
            fmt4.showDialog(dialog, onDismissListener);
        } else if (fragment instanceof BaseFmts) {
            BaseFmts fmt5 = (BaseFmts) fragment;
            fmt5.showDialog(dialog, onDismissListener);
        } else if (fragment instanceof BaseFcFragment) {
            BaseFcFragment fmt6 = (BaseFcFragment) fragment;
            fmt6.showDialog(dialog, onDismissListener);
        }
    }
}
