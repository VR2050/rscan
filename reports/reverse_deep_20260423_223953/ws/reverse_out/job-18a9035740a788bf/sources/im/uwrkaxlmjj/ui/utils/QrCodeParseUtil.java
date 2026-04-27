package im.uwrkaxlmjj.ui.utils;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import androidx.fragment.app.Fragment;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ChatObject;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.DialogsActivity;
import im.uwrkaxlmjj.ui.LaunchActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBarLayout;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.JoinGroupAlert;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.fragments.BaseFmts;
import im.uwrkaxlmjj.ui.hui.chats.NewProfileActivity;
import im.uwrkaxlmjj.ui.hui.contacts.AddContactsInfoActivity;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class QrCodeParseUtil {
    public static void tryParseQrCode(Object hostObj, int currentAccount, String url, boolean removeLast, boolean forceWithoutAnimation, boolean openBowser, boolean allowCustom) {
        tryParseQrCode(hostObj, currentAccount, url, true, removeLast, forceWithoutAnimation, true, false, openBowser, allowCustom);
    }

    /* JADX WARN: Removed duplicated region for block: B:102:0x02f0  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x02d0  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void tryParseQrCode(java.lang.Object r30, int r31, java.lang.String r32, boolean r33, boolean r34, boolean r35, boolean r36, boolean r37, boolean r38, boolean r39) {
        /*
            Method dump skipped, instruction units count: 760
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.utils.QrCodeParseUtil.tryParseQrCode(java.lang.Object, int, java.lang.String, boolean, boolean, boolean, boolean, boolean, boolean, boolean):void");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void runLinkRequest(final Object hostObj, final int currentAccount, final boolean showProgressDialog, final String code, final String username, final String group, final String botUser, final String botChat, final boolean removeLast, final boolean forceWithoutAnimation, final boolean check, final boolean preview, int state) {
        AlertDialog progressDialog;
        AlertDialog progressDialog2;
        final int i;
        if (code != null) {
            if (NotificationCenter.getGlobalInstance().hasObservers(NotificationCenter.didReceiveSmsCode)) {
                NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.didReceiveSmsCode, code);
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(getContext(hostObj));
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder.setMessage(AndroidUtilities.replaceTags(LocaleController.formatString("OtherLoginCode", R.string.OtherLoginCode, code)));
            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
            showDialog(hostObj, builder.create());
            return;
        }
        if (!showProgressDialog) {
            progressDialog = null;
        } else {
            AlertDialog progressDialog3 = new AlertDialog(getContext(hostObj), 3);
            progressDialog = progressDialog3;
        }
        int requestId = 0;
        final AlertDialog finalProgressDialog = progressDialog;
        if (username != null) {
            TLRPC.TL_contacts_resolveUsername req = new TLRPC.TL_contacts_resolveUsername();
            req.username = username;
            progressDialog2 = progressDialog;
            requestId = ConnectionsManager.getInstance(currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.utils.-$$Lambda$QrCodeParseUtil$OFRourMXUBjPx6rCC5kZxWX7RaA
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.utils.-$$Lambda$QrCodeParseUtil$YrkyoyfPH4rrnw8kQoXquN1XKfY
                        @Override // java.lang.Runnable
                        public final void run() {
                            QrCodeParseUtil.lambda$null$1(alertDialog, tLObject, tL_error, obj, i, str, z, z, z, z, str);
                        }
                    });
                }
            });
            i = currentAccount;
        } else {
            progressDialog2 = progressDialog;
            if (group == null) {
                i = currentAccount;
            } else if (state == 0) {
                TLRPC.TL_messages_checkChatInvite req2 = new TLRPC.TL_messages_checkChatInvite();
                req2.hash = group;
                requestId = ConnectionsManager.getInstance(currentAccount).sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.utils.-$$Lambda$QrCodeParseUtil$YjHSCxb7mfyLrB9_OrBaOut9zDw
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.utils.-$$Lambda$QrCodeParseUtil$e-8Tj1eV2fToMmDFYvrmtYiLc8w
                            @Override // java.lang.Runnable
                            public final void run() {
                                QrCodeParseUtil.lambda$null$4(alertDialog, tL_error, obj, tLObject, i, str, z, str, str, str, str, z, z, z, z);
                            }
                        });
                    }
                }, 2);
                i = currentAccount;
            } else if (state == 1) {
                TLRPC.TL_messages_importChatInvite req3 = new TLRPC.TL_messages_importChatInvite();
                req3.hash = group;
                i = currentAccount;
                ConnectionsManager.getInstance(currentAccount).sendRequest(req3, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.utils.-$$Lambda$QrCodeParseUtil$M2wl-ASSlTr3AUsap2VqcdPQQ94
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        QrCodeParseUtil.lambda$runLinkRequest$7(i, finalProgressDialog, hostObj, tLObject, tL_error);
                    }
                }, 2);
            } else {
                i = currentAccount;
            }
        }
        if (requestId != 0 && showProgressDialog) {
            final int finalRequestId = requestId;
            AlertDialog progressDialog4 = progressDialog2;
            progressDialog4.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.utils.-$$Lambda$QrCodeParseUtil$BsI_cPMY_WuGiN12nI94yqD4tQA
                @Override // android.content.DialogInterface.OnCancelListener
                public final void onCancel(DialogInterface dialogInterface) {
                    ConnectionsManager.getInstance(i).cancelRequest(finalRequestId, true);
                }
            });
            try {
                progressDialog4.show();
            } catch (Exception e) {
            }
        }
    }

    static /* synthetic */ void lambda$null$1(AlertDialog finalProgressDialog, TLObject response, TLRPC.TL_error error, final Object hostObj, final int currentAccount, final String botChat, final boolean removeLast, final boolean forceWithoutAnimation, final boolean check, final boolean preview, String botUser) {
        long dialog_id;
        if (finalProgressDialog != null) {
            try {
                finalProgressDialog.dismiss();
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
        TLRPC.TL_contacts_resolvedPeer res = (TLRPC.TL_contacts_resolvedPeer) response;
        if (error == null && getActionLayout(hostObj) != null) {
            MessagesController.getInstance(currentAccount).putUsers(res.users, false);
            MessagesController.getInstance(currentAccount).putChats(res.chats, false);
            MessagesStorage.getInstance(currentAccount).putUsersAndChats(res.users, res.chats, false, true);
            if (botChat != null) {
                final TLRPC.User user = !res.users.isEmpty() ? res.users.get(0) : null;
                if (user == null || (user.bot && user.bot_nochats)) {
                    try {
                        ToastUtils.show(R.string.BotCantJoinGroups);
                        return;
                    } catch (Exception e2) {
                        FileLog.e(e2);
                        return;
                    }
                }
                Bundle args = new Bundle();
                args.putBoolean("onlySelect", true);
                args.putInt("dialogsType", 2);
                args.putString("addToGroupAlertString", LocaleController.formatString("AddToTheGroupTitle", R.string.AddToTheGroupTitle, UserObject.getName(user), "%1$s"));
                DialogsActivity fragment = new DialogsActivity(args);
                fragment.setDelegate(new DialogsActivity.DialogsActivityDelegate() { // from class: im.uwrkaxlmjj.ui.utils.-$$Lambda$QrCodeParseUtil$UCMfmFSAZcRdZv3sEc5fDgPH9yY
                    @Override // im.uwrkaxlmjj.ui.DialogsActivity.DialogsActivityDelegate
                    public final void didSelectDialogs(DialogsActivity dialogsActivity, ArrayList arrayList, CharSequence charSequence, boolean z) {
                        QrCodeParseUtil.lambda$null$0(currentAccount, hostObj, user, botChat, removeLast, forceWithoutAnimation, check, preview, dialogsActivity, arrayList, charSequence, z);
                    }
                });
                presentFragment(hostObj, fragment, removeLast, forceWithoutAnimation, check, preview);
                return;
            }
            boolean isBot = false;
            Bundle args2 = new Bundle();
            if (!res.chats.isEmpty()) {
                args2.putInt("chat_id", res.chats.get(0).id);
                dialog_id = -res.chats.get(0).id;
            } else {
                args2.putInt("user_id", res.users.get(0).id);
                dialog_id = res.users.get(0).id;
            }
            if (botUser != null && res.users.size() > 0 && res.users.get(0).bot) {
                args2.putString("botUser", botUser);
                isBot = true;
            }
            BaseFragment lastFragment = getLastFragment(hostObj);
            if (lastFragment == null || MessagesController.getInstance(currentAccount).checkCanOpenChat(args2, lastFragment)) {
                if (isBot && (lastFragment instanceof ChatActivity) && ((ChatActivity) lastFragment).getDialogId() == dialog_id) {
                    ((ChatActivity) lastFragment).setBotUser(botUser);
                    return;
                } else {
                    presentFragment(hostObj, new ChatActivity(args2), removeLast, forceWithoutAnimation);
                    return;
                }
            }
            return;
        }
        try {
            AlertsCreator.createSimpleAlert(getContext(hostObj), LocaleController.getString("JoinToGroupErrorNotExist", R.string.JoinToGroupErrorNotExist)).show();
        } catch (Exception e3) {
            FileLog.e(e3);
        }
    }

    static /* synthetic */ void lambda$null$0(int currentAccount, Object hostObj, TLRPC.User user, String botChat, boolean removeLast, boolean forceWithoutAnimation, boolean check, boolean preview, DialogsActivity fragment12, ArrayList dids, CharSequence message1, boolean param) {
        long did = ((Long) dids.get(0)).longValue();
        Bundle args12 = new Bundle();
        args12.putBoolean("scrollToTopOnResume", true);
        args12.putInt("chat_id", -((int) did));
        if (MessagesController.getInstance(currentAccount).checkCanOpenChat(args12, getLastFragment(hostObj))) {
            MessagesController.getInstance(currentAccount).addUserToChat(-((int) did), user, null, 0, botChat, null, null);
            presentFragment(hostObj, new ChatActivity(args12), removeLast, forceWithoutAnimation, check, preview);
        }
    }

    static /* synthetic */ void lambda$null$4(AlertDialog finalProgressDialog, TLRPC.TL_error error, final Object hostObj, TLObject response, final int currentAccount, final String group, final boolean showProgressDialog, final String code, final String username, final String botUser, final String botChat, final boolean removeLast, final boolean forceWithoutAnimation, final boolean check, final boolean preview) {
        if (finalProgressDialog != null) {
            try {
                finalProgressDialog.dismiss();
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
        if (error == null && getActionLayout(hostObj) != null) {
            TLRPC.ChatInvite invite = (TLRPC.ChatInvite) response;
            if (invite.chat != null && (!ChatObject.isLeftFromChat(invite.chat) || (!invite.chat.kicked && !TextUtils.isEmpty(invite.chat.username)))) {
                MessagesController.getInstance(currentAccount).putChat(invite.chat, false);
                ArrayList<TLRPC.Chat> chats = new ArrayList<>();
                chats.add(invite.chat);
                MessagesStorage.getInstance(currentAccount).putUsersAndChats(null, chats, false, true);
                Bundle args = new Bundle();
                args.putInt("chat_id", invite.chat.id);
                if (MessagesController.getInstance(currentAccount).checkCanOpenChat(args, getLastFragment(hostObj))) {
                    presentFragment(hostObj, new ChatActivity(args), false, true, true, false);
                }
            } else if (((invite.chat == null && (!invite.channel || invite.megagroup)) || (invite.chat != null && (!ChatObject.isChannel(invite.chat) || invite.chat.megagroup))) && !getActionLayout(hostObj).fragmentsStack.isEmpty()) {
                BaseFragment fragment = getLastFragment(hostObj);
                fragment.showDialog(new JoinGroupAlert(getContext(hostObj), invite, group, fragment));
            } else {
                AlertDialog.Builder builder = new AlertDialog.Builder(getContext(hostObj));
                builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                Object[] objArr = new Object[1];
                objArr[0] = invite.chat != null ? invite.chat.title : invite.title;
                builder.setMessage(LocaleController.formatString("ChannelJoinTo", R.string.ChannelJoinTo, objArr));
                builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.utils.-$$Lambda$QrCodeParseUtil$-F0FJ0KSY28uKg2MyCse1usafbs
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        QrCodeParseUtil.runLinkRequest(hostObj, currentAccount, showProgressDialog, code, username, group, botUser, botChat, removeLast, forceWithoutAnimation, check, preview, 1);
                    }
                });
                builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                showDialog(hostObj, builder.create());
            }
            return;
        }
        AlertDialog.Builder builder2 = new AlertDialog.Builder(getContext(hostObj));
        builder2.setTitle(LocaleController.getString("AppName", R.string.AppName));
        if (error.text.startsWith("FLOOD_WAIT")) {
            builder2.setMessage(LocaleController.getString("FloodWait", R.string.FloodWait));
        } else {
            builder2.setMessage(LocaleController.getString("JoinToGroupErrorNotExist", R.string.JoinToGroupErrorNotExist));
        }
        builder2.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        showDialog(hostObj, builder2.create());
    }

    static /* synthetic */ void lambda$runLinkRequest$7(final int currentAccount, final AlertDialog finalProgressDialog, final Object hostObj, final TLObject response, final TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.Updates updates = (TLRPC.Updates) response;
            MessagesController.getInstance(currentAccount).processUpdates(updates, false);
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.utils.-$$Lambda$QrCodeParseUtil$w0rmz9_aXVzkfLhukwtZdNQXAUE
            @Override // java.lang.Runnable
            public final void run() {
                QrCodeParseUtil.lambda$null$6(finalProgressDialog, error, hostObj, response, currentAccount);
            }
        });
    }

    static /* synthetic */ void lambda$null$6(AlertDialog finalProgressDialog, TLRPC.TL_error error, Object hostObj, TLObject response, int currentAccount) {
        if (finalProgressDialog != null) {
            try {
                finalProgressDialog.dismiss();
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
        if (error == null) {
            if (getActionLayout(hostObj) != null) {
                TLRPC.Updates updates = (TLRPC.Updates) response;
                if (!updates.chats.isEmpty()) {
                    TLRPC.Chat chat = updates.chats.get(0);
                    chat.left = false;
                    chat.kicked = false;
                    MessagesController.getInstance(currentAccount).putUsers(updates.users, false);
                    MessagesController.getInstance(currentAccount).putChats(updates.chats, false);
                    Bundle args = new Bundle();
                    args.putInt("chat_id", chat.id);
                    if (MessagesController.getInstance(currentAccount).checkCanOpenChat(args, getLastFragment(hostObj))) {
                        ChatActivity fragment = new ChatActivity(args);
                        presentFragment(hostObj, fragment, false, true, true, false);
                        return;
                    }
                    return;
                }
                return;
            }
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getContext(hostObj));
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        if (error.text.startsWith("FLOOD_WAIT")) {
            builder.setMessage(LocaleController.getString("FloodWait", R.string.FloodWait));
        } else if (error.text.equals("USERS_TOO_MUCH")) {
            builder.setMessage(LocaleController.getString("JoinToGroupErrorFull", R.string.JoinToGroupErrorFull));
        } else {
            builder.setMessage(LocaleController.getString("JoinToGroupErrorNotExist", R.string.JoinToGroupErrorNotExist));
        }
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        showDialog(hostObj, builder.create());
    }

    private static void tryToGroupOrChannelByUserName(Object hostObj, String userName) {
        MessagesController.getInstance(UserConfig.selectedAccount).openByUserName(userName, getLastFragment(hostObj), 1, true);
    }

    private static void tryToUser(final Object hostObj, final int currentAccount, boolean showProgressDialog, String userId, String userHash, final boolean removeLast, final boolean forceWithoutAnimation) {
        if (TextUtils.isEmpty(userId) || TextUtils.isEmpty(userHash)) {
            return;
        }
        TLRPC.User user = new TLRPC.TL_user();
        user.id = Utilities.parseInt(userId).intValue();
        user.access_hash = Utilities.parseLong(userHash).longValue();
        TLRPC.UserFull userFull = getMessagesController(currentAccount).getUserFull(user.id);
        if (userFull != null) {
            toUser(hostObj, currentAccount, true, userFull, removeLast, forceWithoutAnimation);
            return;
        }
        TLRPC.TL_users_getFullUser req = new TLRPC.TL_users_getFullUser();
        req.id = getMessagesController(currentAccount).getInputUser(user);
        AlertDialog progressDialog = null;
        if (showProgressDialog) {
            progressDialog = new AlertDialog(getContext(hostObj), 3);
            showDialog(hostObj, progressDialog);
        }
        final int reqId = getConnectionsManager(currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.utils.-$$Lambda$QrCodeParseUtil$Mnp09UMbTZZyM7oMdb9hsGhc-Mk
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.utils.-$$Lambda$QrCodeParseUtil$fQJjJ9IRSxcY1nGKGqItzxH2uFI
                    @Override // java.lang.Runnable
                    public final void run() {
                        QrCodeParseUtil.lambda$null$9(tL_error, obj, i, tLObject, z, z);
                    }
                });
            }
        });
        if (progressDialog != null) {
            progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.utils.-$$Lambda$QrCodeParseUtil$ovDq0S1KPrGHH8NiAn9uB6kl5ms
                @Override // android.content.DialogInterface.OnCancelListener
                public final void onCancel(DialogInterface dialogInterface) {
                    QrCodeParseUtil.getConnectionsManager(currentAccount).cancelRequest(reqId, false);
                }
            });
        }
    }

    static /* synthetic */ void lambda$null$9(TLRPC.TL_error error, Object hostObj, int currentAccount, TLObject response, boolean removeLast, boolean forceWithoutAnimation) {
        if (error == null) {
            toUser(hostObj, currentAccount, false, (TLRPC.UserFull) response, removeLast, forceWithoutAnimation);
        } else {
            ToastUtils.show(R.string.NoUsernameFound);
        }
    }

    private static void toUser(Object hostObj, int currentAccount, boolean fromCache, TLRPC.UserFull userFull, boolean removeLast, boolean forceWithoutAnimation) {
        getMessagesController(currentAccount).putUser(userFull.user, false);
        if (userFull.user.self || userFull.user.contact) {
            Bundle bundle = new Bundle();
            bundle.putInt("user_id", userFull.user.id);
            presentFragment(hostObj, new NewProfileActivity(bundle), removeLast, forceWithoutAnimation);
        } else {
            Bundle bundle2 = new Bundle();
            bundle2.putInt("from_type", 1);
            presentFragment(hostObj, new AddContactsInfoActivity(bundle2, userFull.user), removeLast, forceWithoutAnimation);
        }
    }

    private static void presentFragment(Object hostObj, BaseFragment fragment, boolean removeLast, boolean forceWithoutAnimation) {
        presentFragment(hostObj, fragment, removeLast, forceWithoutAnimation, true, false);
    }

    private static void presentFragment(Object hostObj, BaseFragment fragment, boolean removeLast, boolean forceWithoutAnimation, boolean check, boolean preview) {
        ActionBarLayout actionBarLayout;
        if (fragment != null && (actionBarLayout = getActionLayout(hostObj)) != null) {
            actionBarLayout.presentFragment(fragment, removeLast, forceWithoutAnimation, check, preview);
        }
    }

    private static MessagesController getMessagesController(int currentAccount) {
        return MessagesController.getInstance(currentAccount);
    }

    private static MessagesStorage getMessagesStorage(int currentAccount) {
        return MessagesStorage.getInstance(currentAccount);
    }

    private static ConnectionsManager getConnectionsManager(int currentAccount) {
        return ConnectionsManager.getInstance(currentAccount);
    }

    private static Dialog showDialog(Object host, Dialog dialog) {
        if (dialog == null) {
            return null;
        }
        if (host instanceof BaseFragment) {
            return ((BaseFragment) host).showDialog(dialog);
        }
        if (host instanceof BaseFmts) {
            return ((BaseFmts) host).showDialog(dialog);
        }
        if ((host instanceof LaunchActivity) && (dialog instanceof AlertDialog)) {
            return ((LaunchActivity) host).showAlertDialog((AlertDialog) dialog);
        }
        dialog.show();
        return dialog;
    }

    private static void checkHost(Object host) {
        if (!(host instanceof BaseFragment) && !(host instanceof BaseFmts) && !(host instanceof Activity) && !(host instanceof Fragment) && !(host instanceof View) && !(host instanceof Context)) {
            throw new IllegalArgumentException("host must be one of the BaseFragment, BaseFmts, Activity, Fragment, View");
        }
    }

    private static BaseFragment getLastFragment(Object host) {
        ActionBarLayout actionBarLayout = getActionLayout(host);
        if (actionBarLayout != null) {
            return actionBarLayout.getLastFragment();
        }
        return null;
    }

    private static ActionBarLayout getActionLayout(Object host) {
        if (host instanceof BaseFragment) {
            return ((BaseFragment) host).getParentLayout();
        }
        if (host instanceof BaseFmts) {
            return ((BaseFmts) host).getActionBarLayout();
        }
        if (host instanceof LaunchActivity) {
            return ((LaunchActivity) host).getActionBarLayout();
        }
        if (host instanceof ActionBarLayout) {
            return (ActionBarLayout) host;
        }
        return null;
    }

    private static Context getContext(Object host) {
        if (host instanceof BaseFragment) {
            return ((BaseFragment) host).getParentActivity();
        }
        if (host instanceof BaseFmts) {
            return ((BaseFmts) host).getParentActivity();
        }
        if (host instanceof Activity) {
            return (Activity) host;
        }
        if (host instanceof Fragment) {
            return ((Fragment) host).getActivity();
        }
        if (host instanceof View) {
            return ((View) host).getContext();
        }
        if (host instanceof Context) {
            return (Context) host;
        }
        return null;
    }
}
