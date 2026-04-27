package im.uwrkaxlmjj.ui;

import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AccountInstance;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.CheckBoxCell;
import im.uwrkaxlmjj.ui.cells.HeaderCell;
import im.uwrkaxlmjj.ui.cells.TextCheckCell;
import im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell;
import im.uwrkaxlmjj.ui.cells.TextSettingsCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
@Deprecated
public class PrivacySettingsActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private int advancedSectionRow;
    private int blockedRow;
    private int botsDetailRow;
    private int botsSectionRow;
    private int callsRow;
    private boolean[] clear = new boolean[2];
    private int clearDraftsRow;
    private int contactsDeleteRow;
    private int contactsDetailRow;
    private int contactsSectionRow;
    private int contactsSuggestRow;
    private int contactsSyncRow;
    private boolean currentSuggest;
    private boolean currentSync;
    private int deleteAccountDetailRow;
    private int deleteAccountRow;
    private int forwardsRow;
    private int groupsDetailRow;
    private int groupsRow;
    private int lastSeenRow;
    private LinearLayoutManager layoutManager;
    private ListAdapter listAdapter;
    private RecyclerListView listView;
    private boolean newSuggest;
    private boolean newSync;
    private int passcodeRow;
    private int passportRow;
    private int passwordRow;
    private int paymentsClearRow;
    private int phoneNumberRow;
    private int privacySectionRow;
    private int profilePhotoRow;
    private AlertDialog progressDialog;
    private int rowCount;
    private int secretDetailRow;
    private int secretMapRow;
    private int secretSectionRow;
    private int secretWebpageRow;
    private int securitySectionRow;
    private int sessionsDetailRow;
    private int sessionsRow;
    private int webSessionsRow;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        getContactsController().loadPrivacySettings();
        getMessagesController().getBlockedUsers(true);
        boolean z = getUserConfig().syncContacts;
        this.newSync = z;
        this.currentSync = z;
        boolean z2 = getUserConfig().suggestContacts;
        this.newSuggest = z2;
        this.currentSuggest = z2;
        updateRows();
        loadPasswordSettings();
        getNotificationCenter().addObserver(this, NotificationCenter.privacyRulesUpdated);
        getNotificationCenter().addObserver(this, NotificationCenter.blockedUsersDidLoad);
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        getNotificationCenter().removeObserver(this, NotificationCenter.privacyRulesUpdated);
        getNotificationCenter().removeObserver(this, NotificationCenter.blockedUsersDidLoad);
        if (this.currentSync != this.newSync) {
            getUserConfig().syncContacts = this.newSync;
            getUserConfig().saveConfig(false);
            if (this.newSync) {
                getContactsController().forceImportContacts();
                if (getParentActivity() != null) {
                    ToastUtils.show(R.string.SyncContactsAdded);
                }
            }
        }
        boolean z = this.newSuggest;
        if (z != this.currentSuggest) {
            if (!z) {
                getMediaDataController().clearTopPeers();
            }
            getUserConfig().suggestContacts = this.newSuggest;
            getUserConfig().saveConfig(false);
            TLRPC.TL_contacts_toggleTopPeers req = new TLRPC.TL_contacts_toggleTopPeers();
            req.enabled = this.newSuggest;
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacySettingsActivity$YZAOdAUb8JF_xAkPgUigH2FV0Us
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    PrivacySettingsActivity.lambda$onFragmentDestroy$0(tLObject, tL_error);
                }
            });
        }
    }

    static /* synthetic */ void lambda$onFragmentDestroy$0(TLObject response, TLRPC.TL_error error) {
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setTitle(LocaleController.getString("PrivacySettings", R.string.PrivacySettings));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.PrivacySettingsActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    PrivacySettingsActivity.this.finishFragment();
                }
            }
        });
        this.listAdapter = new ListAdapter(context);
        this.fragmentView = new FrameLayout(context);
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        frameLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context, 1, false) { // from class: im.uwrkaxlmjj.ui.PrivacySettingsActivity.2
            @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public boolean supportsPredictiveItemAnimations() {
                return false;
            }
        };
        this.layoutManager = linearLayoutManager;
        recyclerListView.setLayoutManager(linearLayoutManager);
        this.listView.setVerticalScrollBarEnabled(false);
        this.listView.setItemAnimator(null);
        this.listView.setLayoutAnimation(null);
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -1.0f));
        this.listView.setAdapter(this.listAdapter);
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacySettingsActivity$OgqDq4CsKrTP3kaZORcv_qCM6Qk
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$createView$17$PrivacySettingsActivity(view, i);
            }
        });
        return this.fragmentView;
    }

    public /* synthetic */ void lambda$createView$17$PrivacySettingsActivity(View view, int position) {
        if (!view.isEnabled()) {
            return;
        }
        if (position == this.blockedRow) {
            presentFragment(new PrivacyUsersActivity());
            return;
        }
        if (position == this.sessionsRow) {
            presentFragment(new SessionsActivity(0));
            return;
        }
        if (position == this.webSessionsRow) {
            presentFragment(new SessionsActivity(1));
            return;
        }
        if (position == this.clearDraftsRow) {
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder.setMessage(LocaleController.getString("AreYouSureClearDrafts", R.string.AreYouSureClearDrafts));
            builder.setPositiveButton(LocaleController.getString("Delete", R.string.Delete), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacySettingsActivity$Nr_7dbQQ9uREveR1TVnkhdM_FQU
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$3$PrivacySettingsActivity(dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            showDialog(builder.create());
            return;
        }
        if (position == this.deleteAccountRow) {
            if (getParentActivity() == null) {
                return;
            }
            AlertDialog.Builder builder2 = new AlertDialog.Builder(getParentActivity());
            builder2.setTitle(LocaleController.getString("DeleteAccountTitle", R.string.DeleteAccountTitle));
            builder2.setItems(new CharSequence[]{LocaleController.formatPluralString("Months", 1), LocaleController.formatPluralString("Months", 3), LocaleController.formatPluralString("Months", 6), LocaleController.formatPluralString("Years", 1)}, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacySettingsActivity$clFR0ZX7moOgr0w9_nWeLTF0yfk
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$6$PrivacySettingsActivity(dialogInterface, i);
                }
            });
            builder2.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            showDialog(builder2.create());
            return;
        }
        if (position == this.lastSeenRow) {
            presentFragment(new PrivacyControlActivity(0));
            return;
        }
        if (position == this.phoneNumberRow) {
            presentFragment(new PrivacyControlActivity(6));
            return;
        }
        if (position == this.groupsRow) {
            presentFragment(new PrivacyControlActivity(1));
            return;
        }
        if (position == this.callsRow) {
            presentFragment(new PrivacyControlActivity(2));
            return;
        }
        if (position == this.profilePhotoRow) {
            presentFragment(new PrivacyControlActivity(4));
            return;
        }
        if (position == this.forwardsRow) {
            presentFragment(new PrivacyControlActivity(5));
            return;
        }
        if (position == this.passwordRow) {
            presentFragment(new TwoStepVerificationActivity(0));
            return;
        }
        if (position == this.passcodeRow) {
            if (SharedConfig.passcodeHash.length() > 0) {
                presentFragment(new PasscodeActivity(2));
                return;
            } else {
                presentFragment(new PasscodeActivity(0));
                return;
            }
        }
        if (position == this.secretWebpageRow) {
            if (getMessagesController().secretWebpagePreview == 1) {
                getMessagesController().secretWebpagePreview = 0;
            } else {
                getMessagesController().secretWebpagePreview = 1;
            }
            MessagesController.getGlobalMainSettings().edit().putInt("secretWebpage2", getMessagesController().secretWebpagePreview).commit();
            if (view instanceof TextCheckCell) {
                ((TextCheckCell) view).setChecked(getMessagesController().secretWebpagePreview == 1);
                return;
            }
            return;
        }
        if (position == this.contactsDeleteRow) {
            if (getParentActivity() == null) {
                return;
            }
            AlertDialog.Builder builder3 = new AlertDialog.Builder(getParentActivity());
            builder3.setTitle(LocaleController.getString("Contacts", R.string.Contacts));
            builder3.setMessage(LocaleController.getString("SyncContactsDeleteInfo", R.string.SyncContactsDeleteInfo));
            builder3.setPositiveButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            builder3.setNegativeButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacySettingsActivity$oyv33OpCGMGio7itKgAxu4gC7s4
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$8$PrivacySettingsActivity(dialogInterface, i);
                }
            });
            showDialog(builder3.create());
            return;
        }
        if (position == this.contactsSuggestRow) {
            final TextCheckCell cell = (TextCheckCell) view;
            boolean z = this.newSuggest;
            if (z) {
                AlertDialog.Builder builder4 = new AlertDialog.Builder(getParentActivity());
                builder4.setTitle(LocaleController.getString("AppName", R.string.AppName));
                builder4.setMessage(LocaleController.getString("SuggestContactsAlert", R.string.SuggestContactsAlert));
                builder4.setPositiveButton(LocaleController.getString("MuteDisable", R.string.MuteDisable), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacySettingsActivity$ixqFB4U6yEgDgKmzkGKjnTcXS-E
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$null$11$PrivacySettingsActivity(cell, dialogInterface, i);
                    }
                });
                builder4.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                showDialog(builder4.create());
                return;
            }
            boolean z2 = !z;
            this.newSuggest = z2;
            cell.setChecked(z2);
            return;
        }
        if (position == this.contactsSyncRow) {
            boolean z3 = !this.newSync;
            this.newSync = z3;
            if (view instanceof TextCheckCell) {
                ((TextCheckCell) view).setChecked(z3);
                return;
            }
            return;
        }
        if (position == this.secretMapRow) {
            AlertsCreator.showSecretLocationAlert(getParentActivity(), this.currentAccount, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacySettingsActivity$_adXSeYnB0DUVD75bBfj0K7yw_A
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$12$PrivacySettingsActivity();
                }
            }, false);
            return;
        }
        if (position == this.paymentsClearRow) {
            BottomSheet.Builder builder5 = new BottomSheet.Builder(getParentActivity());
            builder5.setApplyTopPadding(false);
            builder5.setApplyBottomPadding(false);
            LinearLayout linearLayout = new LinearLayout(getParentActivity());
            linearLayout.setOrientation(1);
            for (int a = 0; a < 2; a++) {
                String name = null;
                if (a == 0) {
                    name = LocaleController.getString("PrivacyClearShipping", R.string.PrivacyClearShipping);
                } else if (a == 1) {
                    name = LocaleController.getString("PrivacyClearPayment", R.string.PrivacyClearPayment);
                }
                this.clear[a] = true;
                CheckBoxCell checkBoxCell = new CheckBoxCell(getParentActivity(), 1, 21);
                checkBoxCell.setTag(Integer.valueOf(a));
                checkBoxCell.setBackgroundDrawable(Theme.getSelectorDrawable(false));
                linearLayout.addView(checkBoxCell, LayoutHelper.createLinear(-1, 50));
                checkBoxCell.setText(name, null, true, true);
                checkBoxCell.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
                checkBoxCell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacySettingsActivity$KjdnHIrRfHEnH-NNSZHn1atJzVM
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$null$13$PrivacySettingsActivity(view2);
                    }
                });
            }
            BottomSheet.BottomSheetCell cell2 = new BottomSheet.BottomSheetCell(getParentActivity(), 1);
            cell2.setBackgroundDrawable(Theme.getSelectorDrawable(false));
            cell2.setTextAndIcon(LocaleController.getString("ClearButton", R.string.ClearButton).toUpperCase(), 0);
            cell2.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteRedText));
            cell2.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacySettingsActivity$UJYKOv628sheABeGAHj8cmiTCss
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$null$16$PrivacySettingsActivity(view2);
                }
            });
            linearLayout.addView(cell2, LayoutHelper.createLinear(-1, 50));
            builder5.setCustomView(linearLayout);
            showDialog(builder5.create());
            return;
        }
        if (position == this.passportRow) {
            presentFragment(new PassportActivity(5, 0, "", "", (String) null, (String) null, (String) null, (TLRPC.TL_account_authorizationForm) null, (TLRPC.TL_account_password) null));
        }
    }

    public /* synthetic */ void lambda$null$3$PrivacySettingsActivity(DialogInterface dialogInterface, int i) {
        TLRPC.TL_messages_clearAllDrafts req = new TLRPC.TL_messages_clearAllDrafts();
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacySettingsActivity$eW4g28WKJmwDQ9WQ0o5aKV_WOoM
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$null$2$PrivacySettingsActivity(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$null$1$PrivacySettingsActivity() {
        getMediaDataController().clearAllDrafts();
    }

    public /* synthetic */ void lambda$null$2$PrivacySettingsActivity(TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacySettingsActivity$mrXvmtJo1M-bsj_NLoAmLz6J_lc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$1$PrivacySettingsActivity();
            }
        });
    }

    public /* synthetic */ void lambda$null$6$PrivacySettingsActivity(DialogInterface dialog, int which) {
        int value = 0;
        if (which == 0) {
            value = 30;
        } else if (which == 1) {
            value = 90;
        } else if (which == 2) {
            value = 182;
        } else if (which == 3) {
            value = 365;
        }
        final AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        progressDialog.setCanCancel(false);
        progressDialog.show();
        final TLRPC.TL_account_setAccountTTL req = new TLRPC.TL_account_setAccountTTL();
        req.ttl = new TLRPC.TL_accountDaysTTL();
        req.ttl.days = value;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacySettingsActivity$OYEIo0stff76BWMaKJEib9Diz_Q
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$null$5$PrivacySettingsActivity(progressDialog, req, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$null$5$PrivacySettingsActivity(final AlertDialog progressDialog, final TLRPC.TL_account_setAccountTTL req, final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacySettingsActivity$X_NrHTyLGWf7x71pnTbcX2W26o8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$4$PrivacySettingsActivity(progressDialog, response, req);
            }
        });
    }

    public /* synthetic */ void lambda$null$4$PrivacySettingsActivity(AlertDialog progressDialog, TLObject response, TLRPC.TL_account_setAccountTTL req) {
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
        if (response instanceof TLRPC.TL_boolTrue) {
            getContactsController().setDeleteAccountTTL(req.ttl.days);
            this.listAdapter.notifyDataSetChanged();
        }
    }

    public /* synthetic */ void lambda$null$8$PrivacySettingsActivity(DialogInterface dialogInterface, int i) {
        AlertDialog.Builder builder12 = new AlertDialog.Builder(getParentActivity(), 3);
        AlertDialog alertDialogShow = builder12.show();
        this.progressDialog = alertDialogShow;
        alertDialogShow.setCanCancel(false);
        if (this.currentSync != this.newSync) {
            UserConfig userConfig = getUserConfig();
            boolean z = this.newSync;
            userConfig.syncContacts = z;
            this.currentSync = z;
            getUserConfig().saveConfig(false);
        }
        getContactsController().deleteAllContacts(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacySettingsActivity$qk7vBB7EvETvlSTyiv26u-XXN54
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$7$PrivacySettingsActivity();
            }
        });
    }

    public /* synthetic */ void lambda$null$7$PrivacySettingsActivity() {
        this.progressDialog.dismiss();
    }

    public /* synthetic */ void lambda$null$11$PrivacySettingsActivity(final TextCheckCell cell, DialogInterface dialogInterface, int i) {
        TLRPC.TL_payments_clearSavedInfo req = new TLRPC.TL_payments_clearSavedInfo();
        req.credentials = this.clear[1];
        req.info = this.clear[0];
        getUserConfig().tmpPassword = null;
        getUserConfig().saveConfig(false);
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacySettingsActivity$-jKPCrNINjIWpz3y2D8RB1IfCy4
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$null$10$PrivacySettingsActivity(cell, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$null$10$PrivacySettingsActivity(final TextCheckCell cell, TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacySettingsActivity$RSuTlrX-QvyyIy4-oWOizbmLQnc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$9$PrivacySettingsActivity(cell);
            }
        });
    }

    public /* synthetic */ void lambda$null$9$PrivacySettingsActivity(TextCheckCell cell) {
        boolean z = !this.newSuggest;
        this.newSuggest = z;
        cell.setChecked(z);
    }

    public /* synthetic */ void lambda$null$12$PrivacySettingsActivity() {
        this.listAdapter.notifyDataSetChanged();
    }

    public /* synthetic */ void lambda$null$13$PrivacySettingsActivity(View v) {
        CheckBoxCell cell = (CheckBoxCell) v;
        int num = ((Integer) cell.getTag()).intValue();
        boolean[] zArr = this.clear;
        zArr[num] = !zArr[num];
        cell.setChecked(zArr[num], true);
    }

    public /* synthetic */ void lambda$null$16$PrivacySettingsActivity(View v) {
        try {
            if (this.visibleDialog != null) {
                this.visibleDialog.dismiss();
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        AlertDialog.Builder builder1 = new AlertDialog.Builder(getParentActivity());
        builder1.setTitle(LocaleController.getString("AppName", R.string.AppName));
        builder1.setMessage(LocaleController.getString("PrivacyPaymentsClearAlert", R.string.PrivacyPaymentsClearAlert));
        builder1.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacySettingsActivity$cxfbSauqWbzmVeRZnrPoHApgJzo
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$null$15$PrivacySettingsActivity(dialogInterface, i);
            }
        });
        builder1.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        showDialog(builder1.create());
    }

    public /* synthetic */ void lambda$null$15$PrivacySettingsActivity(DialogInterface dialogInterface, int i) {
        TLRPC.TL_payments_clearSavedInfo req = new TLRPC.TL_payments_clearSavedInfo();
        req.credentials = this.clear[1];
        req.info = this.clear[0];
        getUserConfig().tmpPassword = null;
        getUserConfig().saveConfig(false);
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacySettingsActivity$g1x33dxS8FvRgKQ65r_Z5a5NKlI
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                PrivacySettingsActivity.lambda$null$14(tLObject, tL_error);
            }
        });
    }

    static /* synthetic */ void lambda$null$14(TLObject response, TLRPC.TL_error error) {
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.privacyRulesUpdated) {
            ListAdapter listAdapter = this.listAdapter;
            if (listAdapter != null) {
                listAdapter.notifyDataSetChanged();
                return;
            }
            return;
        }
        if (id == NotificationCenter.blockedUsersDidLoad) {
            this.listAdapter.notifyItemChanged(this.blockedRow);
        }
    }

    private void updateRows() {
        this.rowCount = 0;
        int i = 0 + 1;
        this.rowCount = i;
        this.privacySectionRow = 0;
        int i2 = i + 1;
        this.rowCount = i2;
        this.blockedRow = i;
        int i3 = i2 + 1;
        this.rowCount = i3;
        this.phoneNumberRow = i2;
        int i4 = i3 + 1;
        this.rowCount = i4;
        this.lastSeenRow = i3;
        int i5 = i4 + 1;
        this.rowCount = i5;
        this.profilePhotoRow = i4;
        int i6 = i5 + 1;
        this.rowCount = i6;
        this.forwardsRow = i5;
        int i7 = i6 + 1;
        this.rowCount = i7;
        this.callsRow = i6;
        int i8 = i7 + 1;
        this.rowCount = i8;
        this.groupsRow = i7;
        int i9 = i8 + 1;
        this.rowCount = i9;
        this.groupsDetailRow = i8;
        int i10 = i9 + 1;
        this.rowCount = i10;
        this.securitySectionRow = i9;
        int i11 = i10 + 1;
        this.rowCount = i11;
        this.passcodeRow = i10;
        int i12 = i11 + 1;
        this.rowCount = i12;
        this.passwordRow = i11;
        this.sessionsRow = -1;
        int i13 = i12 + 1;
        this.rowCount = i13;
        this.sessionsDetailRow = i12;
        int i14 = i13 + 1;
        this.rowCount = i14;
        this.advancedSectionRow = i13;
        int i15 = i14 + 1;
        this.rowCount = i15;
        this.clearDraftsRow = i14;
        int i16 = i15 + 1;
        this.rowCount = i16;
        this.deleteAccountRow = i15;
        int i17 = i16 + 1;
        this.rowCount = i17;
        this.deleteAccountDetailRow = i16;
        this.rowCount = i17 + 1;
        this.botsSectionRow = i17;
        if (getUserConfig().hasSecureData) {
            int i18 = this.rowCount;
            this.rowCount = i18 + 1;
            this.passportRow = i18;
        } else {
            this.passportRow = -1;
        }
        int i19 = this.rowCount;
        int i20 = i19 + 1;
        this.rowCount = i20;
        this.paymentsClearRow = i19;
        int i21 = i20 + 1;
        this.rowCount = i21;
        this.webSessionsRow = i20;
        int i22 = i21 + 1;
        this.rowCount = i22;
        this.botsDetailRow = i21;
        int i23 = i22 + 1;
        this.rowCount = i23;
        this.contactsSectionRow = i22;
        int i24 = i23 + 1;
        this.rowCount = i24;
        this.contactsDeleteRow = i23;
        int i25 = i24 + 1;
        this.rowCount = i25;
        this.contactsSyncRow = i24;
        int i26 = i25 + 1;
        this.rowCount = i26;
        this.contactsSuggestRow = i25;
        int i27 = i26 + 1;
        this.rowCount = i27;
        this.contactsDetailRow = i26;
        int i28 = i27 + 1;
        this.rowCount = i28;
        this.secretSectionRow = i27;
        int i29 = i28 + 1;
        this.rowCount = i29;
        this.secretMapRow = i28;
        int i30 = i29 + 1;
        this.rowCount = i30;
        this.secretWebpageRow = i29;
        this.rowCount = i30 + 1;
        this.secretDetailRow = i30;
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    private void loadPasswordSettings() {
        if (getUserConfig().hasSecureData) {
            return;
        }
        TLRPC.TL_account_getPassword req = new TLRPC.TL_account_getPassword();
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacySettingsActivity$ecjphMz-JDyhScpBvt7EGjGeV5o
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadPasswordSettings$19$PrivacySettingsActivity(tLObject, tL_error);
            }
        }, 10);
    }

    public /* synthetic */ void lambda$loadPasswordSettings$19$PrivacySettingsActivity(TLObject response, TLRPC.TL_error error) {
        if (response != null) {
            TLRPC.TL_account_password password = (TLRPC.TL_account_password) response;
            if (password.has_secure_values) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PrivacySettingsActivity$YoJlZ-ZoJ7CxlMIhaLOARlM-2IU
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$18$PrivacySettingsActivity();
                    }
                });
            }
        }
    }

    public /* synthetic */ void lambda$null$18$PrivacySettingsActivity() {
        getUserConfig().hasSecureData = true;
        getUserConfig().saveConfig(false);
        updateRows();
    }

    public static String formatRulesString(AccountInstance accountInstance, int rulesType) {
        ArrayList<TLRPC.PrivacyRule> privacyRules = accountInstance.getContactsController().getPrivacyRules(rulesType);
        if (privacyRules.size() == 0) {
            if (rulesType == 3) {
                return LocaleController.getString("P2PNobody", R.string.P2PNobody);
            }
            return LocaleController.getString("LastSeenNobody", R.string.LastSeenNobody);
        }
        int type = -1;
        int plus = 0;
        int minus = 0;
        for (int a = 0; a < privacyRules.size(); a++) {
            TLRPC.PrivacyRule rule = privacyRules.get(a);
            if (rule instanceof TLRPC.TL_privacyValueAllowChatParticipants) {
                TLRPC.TL_privacyValueAllowChatParticipants participants = (TLRPC.TL_privacyValueAllowChatParticipants) rule;
                int N = participants.chats.size();
                for (int b = 0; b < N; b++) {
                    TLRPC.Chat chat = accountInstance.getMessagesController().getChat(participants.chats.get(b));
                    if (chat != null) {
                        plus += chat.participants_count;
                    }
                }
            } else if (rule instanceof TLRPC.TL_privacyValueDisallowChatParticipants) {
                TLRPC.TL_privacyValueDisallowChatParticipants participants2 = (TLRPC.TL_privacyValueDisallowChatParticipants) rule;
                int N2 = participants2.chats.size();
                for (int b2 = 0; b2 < N2; b2++) {
                    TLRPC.Chat chat2 = accountInstance.getMessagesController().getChat(participants2.chats.get(b2));
                    if (chat2 != null) {
                        minus += chat2.participants_count;
                    }
                }
            } else if (rule instanceof TLRPC.TL_privacyValueAllowUsers) {
                TLRPC.TL_privacyValueAllowUsers privacyValueAllowUsers = (TLRPC.TL_privacyValueAllowUsers) rule;
                plus += privacyValueAllowUsers.users.size();
            } else if (rule instanceof TLRPC.TL_privacyValueDisallowUsers) {
                TLRPC.TL_privacyValueDisallowUsers privacyValueDisallowUsers = (TLRPC.TL_privacyValueDisallowUsers) rule;
                minus += privacyValueDisallowUsers.users.size();
            } else if (type == -1) {
                if (rule instanceof TLRPC.TL_privacyValueAllowAll) {
                    type = 0;
                } else if (rule instanceof TLRPC.TL_privacyValueDisallowAll) {
                    type = 1;
                } else {
                    type = 2;
                }
            }
        }
        if (type == 0 || (type == -1 && minus > 0)) {
            if (rulesType == 3) {
                if (minus == 0) {
                    return LocaleController.getString("P2PEverybody", R.string.P2PEverybody);
                }
                return LocaleController.formatString("P2PEverybodyMinus", R.string.P2PEverybodyMinus, Integer.valueOf(minus));
            }
            if (minus == 0) {
                return LocaleController.getString("LastSeenEverybody", R.string.LastSeenEverybody);
            }
            return LocaleController.formatString("LastSeenEverybodyMinus", R.string.LastSeenEverybodyMinus, Integer.valueOf(minus));
        }
        if (type == 2 || (type == -1 && minus > 0 && plus > 0)) {
            if (rulesType == 3) {
                if (plus == 0 && minus == 0) {
                    return LocaleController.getString("P2PContacts", R.string.P2PContacts);
                }
                if (plus != 0 && minus != 0) {
                    return LocaleController.formatString("P2PContactsMinusPlus", R.string.P2PContactsMinusPlus, Integer.valueOf(minus), Integer.valueOf(plus));
                }
                if (minus != 0) {
                    return LocaleController.formatString("P2PContactsMinus", R.string.P2PContactsMinus, Integer.valueOf(minus));
                }
                return LocaleController.formatString("P2PContactsPlus", R.string.P2PContactsPlus, Integer.valueOf(plus));
            }
            if (plus == 0 && minus == 0) {
                return LocaleController.getString("LastSeenContacts", R.string.LastSeenContacts);
            }
            if (plus != 0 && minus != 0) {
                return LocaleController.formatString("LastSeenContactsMinusPlus", R.string.LastSeenContactsMinusPlus, Integer.valueOf(minus), Integer.valueOf(plus));
            }
            if (minus != 0) {
                return LocaleController.formatString("LastSeenContactsMinus", R.string.LastSeenContactsMinus, Integer.valueOf(minus));
            }
            return LocaleController.formatString("LastSeenContactsPlus", R.string.LastSeenContactsPlus, Integer.valueOf(plus));
        }
        if (type == 1 || plus > 0) {
            if (rulesType == 3) {
                if (plus == 0) {
                    return LocaleController.getString("P2PNobody", R.string.P2PNobody);
                }
                return LocaleController.formatString("P2PNobodyPlus", R.string.P2PNobodyPlus, Integer.valueOf(plus));
            }
            if (plus == 0) {
                return LocaleController.getString("LastSeenNobody", R.string.LastSeenNobody);
            }
            return LocaleController.formatString("LastSeenNobodyPlus", R.string.LastSeenNobodyPlus, Integer.valueOf(plus));
        }
        return "unknown";
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int position = holder.getAdapterPosition();
            return position == PrivacySettingsActivity.this.passcodeRow || position == PrivacySettingsActivity.this.passwordRow || position == PrivacySettingsActivity.this.blockedRow || position == PrivacySettingsActivity.this.sessionsRow || position == PrivacySettingsActivity.this.secretWebpageRow || position == PrivacySettingsActivity.this.webSessionsRow || position == PrivacySettingsActivity.this.clearDraftsRow || (position == PrivacySettingsActivity.this.groupsRow && !PrivacySettingsActivity.this.getContactsController().getLoadingPrivicyInfo(1)) || ((position == PrivacySettingsActivity.this.lastSeenRow && !PrivacySettingsActivity.this.getContactsController().getLoadingPrivicyInfo(0)) || ((position == PrivacySettingsActivity.this.callsRow && !PrivacySettingsActivity.this.getContactsController().getLoadingPrivicyInfo(2)) || ((position == PrivacySettingsActivity.this.profilePhotoRow && !PrivacySettingsActivity.this.getContactsController().getLoadingPrivicyInfo(4)) || ((position == PrivacySettingsActivity.this.forwardsRow && !PrivacySettingsActivity.this.getContactsController().getLoadingPrivicyInfo(5)) || ((position == PrivacySettingsActivity.this.phoneNumberRow && !PrivacySettingsActivity.this.getContactsController().getLoadingPrivicyInfo(6)) || ((position == PrivacySettingsActivity.this.deleteAccountRow && !PrivacySettingsActivity.this.getContactsController().getLoadingDeleteInfo()) || position == PrivacySettingsActivity.this.paymentsClearRow || position == PrivacySettingsActivity.this.secretMapRow || position == PrivacySettingsActivity.this.contactsSyncRow || position == PrivacySettingsActivity.this.passportRow || position == PrivacySettingsActivity.this.contactsDeleteRow || position == PrivacySettingsActivity.this.contactsSuggestRow))))));
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return PrivacySettingsActivity.this.rowCount;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                view = new TextSettingsCell(this.mContext);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == 1) {
                view = new TextInfoPrivacyCell(this.mContext);
            } else if (viewType == 2) {
                view = new HeaderCell(this.mContext);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else {
                view = new TextCheckCell(this.mContext);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            String value;
            String value2;
            String value3;
            String value4;
            String value5;
            String value6;
            String value7;
            String value8;
            int itemViewType = holder.getItemViewType();
            if (itemViewType != 0) {
                if (itemViewType == 1) {
                    TextInfoPrivacyCell privacyCell = (TextInfoPrivacyCell) holder.itemView;
                    if (position != PrivacySettingsActivity.this.deleteAccountDetailRow) {
                        if (position != PrivacySettingsActivity.this.groupsDetailRow) {
                            if (position != PrivacySettingsActivity.this.sessionsDetailRow) {
                                if (position != PrivacySettingsActivity.this.secretDetailRow) {
                                    if (position != PrivacySettingsActivity.this.botsDetailRow) {
                                        if (position == PrivacySettingsActivity.this.contactsDetailRow) {
                                            privacyCell.setText(LocaleController.getString("SuggestContactsInfo", R.string.SuggestContactsInfo));
                                            privacyCell.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
                                            return;
                                        }
                                        return;
                                    }
                                    privacyCell.setText(LocaleController.getString("PrivacyBotsInfo", R.string.PrivacyBotsInfo));
                                    privacyCell.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
                                    return;
                                }
                                privacyCell.setText(LocaleController.getString("SecretWebPageInfo", R.string.SecretWebPageInfo));
                                privacyCell.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
                                return;
                            }
                            privacyCell.setText(LocaleController.getString("SessionsInfo", R.string.SessionsInfo));
                            privacyCell.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
                            return;
                        }
                        privacyCell.setText(LocaleController.getString("GroupsAndChannelsHelp", R.string.GroupsAndChannelsHelp));
                        privacyCell.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
                        return;
                    }
                    privacyCell.setText(LocaleController.getString("DeleteAccountHelp", R.string.DeleteAccountHelp));
                    privacyCell.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
                    return;
                }
                if (itemViewType != 2) {
                    if (itemViewType == 3) {
                        TextCheckCell textCheckCell = (TextCheckCell) holder.itemView;
                        if (position == PrivacySettingsActivity.this.secretWebpageRow) {
                            textCheckCell.setTextAndCheck(LocaleController.getString("SecretWebPage", R.string.SecretWebPage), PrivacySettingsActivity.this.getMessagesController().secretWebpagePreview == 1, false);
                            return;
                        } else if (position == PrivacySettingsActivity.this.contactsSyncRow) {
                            textCheckCell.setTextAndCheck(LocaleController.getString("SyncContacts", R.string.SyncContacts), PrivacySettingsActivity.this.newSync, true);
                            return;
                        } else {
                            if (position == PrivacySettingsActivity.this.contactsSuggestRow) {
                                textCheckCell.setTextAndCheck(LocaleController.getString("SuggestContacts", R.string.SuggestContacts), PrivacySettingsActivity.this.newSuggest, false);
                                return;
                            }
                            return;
                        }
                    }
                    return;
                }
                HeaderCell headerCell = (HeaderCell) holder.itemView;
                if (position != PrivacySettingsActivity.this.privacySectionRow) {
                    if (position != PrivacySettingsActivity.this.securitySectionRow) {
                        if (position != PrivacySettingsActivity.this.advancedSectionRow) {
                            if (position != PrivacySettingsActivity.this.secretSectionRow) {
                                if (position != PrivacySettingsActivity.this.botsSectionRow) {
                                    if (position == PrivacySettingsActivity.this.contactsSectionRow) {
                                        headerCell.setText(LocaleController.getString("Contacts", R.string.Contacts));
                                        return;
                                    }
                                    return;
                                }
                                headerCell.setText(LocaleController.getString("PrivacyBots", R.string.PrivacyBots));
                                return;
                            }
                            headerCell.setText(LocaleController.getString("SecretChat", R.string.SecretChat));
                            return;
                        }
                        headerCell.setText(LocaleController.getString("PrivacyAdvanced", R.string.PrivacyAdvanced));
                        return;
                    }
                    headerCell.setText(LocaleController.getString("SecurityTitle", R.string.SecurityTitle));
                    return;
                }
                headerCell.setText(LocaleController.getString("PrivacyTitle", R.string.PrivacyTitle));
                return;
            }
            TextSettingsCell textCell = (TextSettingsCell) holder.itemView;
            if (position == PrivacySettingsActivity.this.blockedRow) {
                int totalCount = PrivacySettingsActivity.this.getMessagesController().totalBlockedCount;
                if (totalCount == 0) {
                    textCell.setTextAndValue(LocaleController.getString("BlockedUsers", R.string.BlockedUsers), LocaleController.getString("BlockedEmpty", R.string.BlockedEmpty), true);
                    return;
                } else if (totalCount > 0) {
                    textCell.setTextAndValue(LocaleController.getString("BlockedUsers", R.string.BlockedUsers), String.format("%d", Integer.valueOf(totalCount)), true);
                    return;
                } else {
                    textCell.setText(LocaleController.getString("BlockedUsers", R.string.BlockedUsers), true);
                    return;
                }
            }
            if (position != PrivacySettingsActivity.this.sessionsRow) {
                if (position != PrivacySettingsActivity.this.webSessionsRow) {
                    if (position != PrivacySettingsActivity.this.passwordRow) {
                        if (position != PrivacySettingsActivity.this.passcodeRow) {
                            if (position == PrivacySettingsActivity.this.phoneNumberRow) {
                                if (PrivacySettingsActivity.this.getContactsController().getLoadingPrivicyInfo(6)) {
                                    value8 = LocaleController.getString("Loading", R.string.Loading);
                                } else {
                                    value8 = PrivacySettingsActivity.formatRulesString(PrivacySettingsActivity.this.getAccountInstance(), 6);
                                }
                                textCell.setTextAndValue(LocaleController.getString("PrivacyPhone", R.string.PrivacyPhone), value8, true);
                                return;
                            }
                            if (position == PrivacySettingsActivity.this.lastSeenRow) {
                                if (PrivacySettingsActivity.this.getContactsController().getLoadingPrivicyInfo(0)) {
                                    value7 = LocaleController.getString("Loading", R.string.Loading);
                                } else {
                                    value7 = PrivacySettingsActivity.formatRulesString(PrivacySettingsActivity.this.getAccountInstance(), 0);
                                }
                                textCell.setTextAndValue(LocaleController.getString("PrivacyLastSeen", R.string.PrivacyLastSeen), value7, true);
                                return;
                            }
                            if (position == PrivacySettingsActivity.this.groupsRow) {
                                if (PrivacySettingsActivity.this.getContactsController().getLoadingPrivicyInfo(1)) {
                                    value6 = LocaleController.getString("Loading", R.string.Loading);
                                } else {
                                    value6 = PrivacySettingsActivity.formatRulesString(PrivacySettingsActivity.this.getAccountInstance(), 1);
                                }
                                textCell.setTextAndValue(LocaleController.getString("GroupsAndChannels", R.string.GroupsAndChannels), value6, false);
                                return;
                            }
                            if (position == PrivacySettingsActivity.this.callsRow) {
                                if (PrivacySettingsActivity.this.getContactsController().getLoadingPrivicyInfo(2)) {
                                    value5 = LocaleController.getString("Loading", R.string.Loading);
                                } else {
                                    value5 = PrivacySettingsActivity.formatRulesString(PrivacySettingsActivity.this.getAccountInstance(), 2);
                                }
                                textCell.setTextAndValue(LocaleController.getString("Calls", R.string.Calls), value5, true);
                                return;
                            }
                            if (position == PrivacySettingsActivity.this.profilePhotoRow) {
                                if (PrivacySettingsActivity.this.getContactsController().getLoadingPrivicyInfo(4)) {
                                    value4 = LocaleController.getString("Loading", R.string.Loading);
                                } else {
                                    value4 = PrivacySettingsActivity.formatRulesString(PrivacySettingsActivity.this.getAccountInstance(), 4);
                                }
                                textCell.setTextAndValue(LocaleController.getString("PrivacyProfilePhoto", R.string.PrivacyProfilePhoto), value4, true);
                                return;
                            }
                            if (position == PrivacySettingsActivity.this.forwardsRow) {
                                if (PrivacySettingsActivity.this.getContactsController().getLoadingPrivicyInfo(5)) {
                                    value3 = LocaleController.getString("Loading", R.string.Loading);
                                } else {
                                    value3 = PrivacySettingsActivity.formatRulesString(PrivacySettingsActivity.this.getAccountInstance(), 5);
                                }
                                textCell.setTextAndValue(LocaleController.getString("PrivacyForwards", R.string.PrivacyForwards), value3, true);
                                return;
                            }
                            if (position != PrivacySettingsActivity.this.passportRow) {
                                if (position == PrivacySettingsActivity.this.deleteAccountRow) {
                                    if (!PrivacySettingsActivity.this.getContactsController().getLoadingDeleteInfo()) {
                                        int ttl = PrivacySettingsActivity.this.getContactsController().getDeleteAccountTTL();
                                        if (ttl <= 182) {
                                            value2 = LocaleController.formatPluralString("Months", ttl / 30);
                                        } else if (ttl == 365) {
                                            value2 = LocaleController.formatPluralString("Years", ttl / 365);
                                        } else {
                                            value2 = LocaleController.formatPluralString("Days", ttl);
                                        }
                                    } else {
                                        value2 = LocaleController.getString("Loading", R.string.Loading);
                                    }
                                    textCell.setTextAndValue(LocaleController.getString("DeleteAccountIfAwayFor2", R.string.DeleteAccountIfAwayFor2), value2, false);
                                    return;
                                }
                                if (position != PrivacySettingsActivity.this.clearDraftsRow) {
                                    if (position != PrivacySettingsActivity.this.paymentsClearRow) {
                                        if (position != PrivacySettingsActivity.this.secretMapRow) {
                                            if (position == PrivacySettingsActivity.this.contactsDeleteRow) {
                                                textCell.setText(LocaleController.getString("SyncContactsDelete", R.string.SyncContactsDelete), true);
                                                return;
                                            }
                                            return;
                                        }
                                        int i = SharedConfig.mapPreviewType;
                                        if (i == 0) {
                                            value = LocaleController.getString("MapPreviewProviderApp", R.string.MapPreviewProviderApp);
                                        } else if (i == 1) {
                                            value = LocaleController.getString("MapPreviewProviderGoogle", R.string.MapPreviewProviderGoogle);
                                        } else {
                                            value = LocaleController.getString("MapPreviewProviderNobody", R.string.MapPreviewProviderNobody);
                                        }
                                        textCell.setTextAndValue(LocaleController.getString("MapPreviewProvider", R.string.MapPreviewProvider), value, true);
                                        return;
                                    }
                                    textCell.setText(LocaleController.getString("PrivacyPaymentsClear", R.string.PrivacyPaymentsClear), true);
                                    return;
                                }
                                textCell.setText(LocaleController.getString("PrivacyDeleteCloudDrafts", R.string.PrivacyDeleteCloudDrafts), true);
                                return;
                            }
                            textCell.setText(LocaleController.getString("AppPassport", R.string.AppPassport), true);
                            return;
                        }
                        textCell.setText(LocaleController.getString("Passcode", R.string.Passcode), true);
                        return;
                    }
                    textCell.setText(LocaleController.getString("TwoStepVerification", R.string.TwoStepVerification), true);
                    return;
                }
                textCell.setText(LocaleController.getString("WebSessionsTitle", R.string.WebSessionsTitle), false);
                return;
            }
            textCell.setText(LocaleController.getString("SessionsTitle", R.string.SessionsTitle), false);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position == PrivacySettingsActivity.this.passportRow || position == PrivacySettingsActivity.this.lastSeenRow || position == PrivacySettingsActivity.this.phoneNumberRow || position == PrivacySettingsActivity.this.blockedRow || position == PrivacySettingsActivity.this.deleteAccountRow || position == PrivacySettingsActivity.this.sessionsRow || position == PrivacySettingsActivity.this.webSessionsRow || position == PrivacySettingsActivity.this.passwordRow || position == PrivacySettingsActivity.this.passcodeRow || position == PrivacySettingsActivity.this.groupsRow || position == PrivacySettingsActivity.this.paymentsClearRow || position == PrivacySettingsActivity.this.secretMapRow || position == PrivacySettingsActivity.this.contactsDeleteRow || position == PrivacySettingsActivity.this.clearDraftsRow) {
                return 0;
            }
            if (position != PrivacySettingsActivity.this.deleteAccountDetailRow && position != PrivacySettingsActivity.this.groupsDetailRow && position != PrivacySettingsActivity.this.sessionsDetailRow && position != PrivacySettingsActivity.this.secretDetailRow && position != PrivacySettingsActivity.this.botsDetailRow && position != PrivacySettingsActivity.this.contactsDetailRow) {
                if (position == PrivacySettingsActivity.this.securitySectionRow || position == PrivacySettingsActivity.this.advancedSectionRow || position == PrivacySettingsActivity.this.privacySectionRow || position == PrivacySettingsActivity.this.secretSectionRow || position == PrivacySettingsActivity.this.botsSectionRow || position == PrivacySettingsActivity.this.contactsSectionRow) {
                    return 2;
                }
                return (position == PrivacySettingsActivity.this.secretWebpageRow || position == PrivacySettingsActivity.this.contactsSyncRow || position == PrivacySettingsActivity.this.contactsSuggestRow) ? 3 : 0;
            }
            return 1;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        return new ThemeDescription[]{new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{TextSettingsCell.class, HeaderCell.class, TextCheckCell.class}, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteValueText), new ThemeDescription(this.listView, 0, new Class[]{HeaderCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueHeader), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{TextInfoPrivacyCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrack), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrackChecked)};
    }
}
