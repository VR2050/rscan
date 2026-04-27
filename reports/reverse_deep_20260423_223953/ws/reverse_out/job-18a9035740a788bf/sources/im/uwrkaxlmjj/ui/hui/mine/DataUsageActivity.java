package im.uwrkaxlmjj.ui.hui.mine;

import android.content.Context;
import android.content.DialogInterface;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.CheckBoxCell;
import im.uwrkaxlmjj.ui.cells.HeaderCell;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hcells.MryTextCheckCell;
import im.uwrkaxlmjj.ui.hcells.TextSettingCell;
import im.uwrkaxlmjj.ui.hui.mine.DataUsageActivity;
import im.uwrkaxlmjj.ui.hviews.dialogs.XDialog;
import im.uwrkaxlmjj.ui.hviews.dialogs.XDialogStyle;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class DataUsageActivity extends BaseFragment {
    private ListAdapter adapter;
    private boolean[] clear = new boolean[2];
    private int contacstSectionRow;
    private boolean currentSuggest;
    private boolean currentSync;
    private int deleteDraftRow;
    private int deletePayInfoDetailRow;
    private int deletePayInfoRow;
    private int dialogSectionEmptyRow;
    private int dialogSectionRow;
    private int emptyRow;
    private int likReviewDetailRow;
    private int linkReviewRow;
    private RecyclerListView listView;
    private Context mContext;
    private boolean newSuggest;
    private boolean newSync;
    private int paySectionRow;
    private AlertDialog progressDialog;
    private int recommenBusyContactsDetailRow;
    private int recommendBusyContactRow;
    private int rowCount;
    private int secureSectionRow;
    private int sycnContactsRow;
    private int syncContactsDetailRow;

    private void updateRows() {
        this.rowCount = 0;
        int i = 0 + 1;
        this.rowCount = i;
        this.emptyRow = 0;
        int i2 = i + 1;
        this.rowCount = i2;
        this.contacstSectionRow = i;
        int i3 = i2 + 1;
        this.rowCount = i3;
        this.sycnContactsRow = i2;
        int i4 = i3 + 1;
        this.rowCount = i4;
        this.syncContactsDetailRow = i3;
        int i5 = i4 + 1;
        this.rowCount = i5;
        this.recommendBusyContactRow = i4;
        int i6 = i5 + 1;
        this.rowCount = i6;
        this.recommenBusyContactsDetailRow = i5;
        int i7 = i6 + 1;
        this.rowCount = i7;
        this.dialogSectionRow = i6;
        int i8 = i7 + 1;
        this.rowCount = i8;
        this.deleteDraftRow = i7;
        int i9 = i8 + 1;
        this.rowCount = i9;
        this.dialogSectionEmptyRow = i8;
        this.paySectionRow = -1;
        this.deletePayInfoRow = -1;
        this.deletePayInfoDetailRow = -1;
        int i10 = i9 + 1;
        this.rowCount = i10;
        this.secureSectionRow = i9;
        int i11 = i10 + 1;
        this.rowCount = i11;
        this.linkReviewRow = i10;
        this.rowCount = i11 + 1;
        this.likReviewDetailRow = i11;
    }

    private void initActionBar() {
        this.actionBar.setTitle(LocaleController.getString("DataUsageSetting", R.string.DataUsageSetting));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.mine.DataUsageActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    DataUsageActivity.this.finishFragment();
                }
            }
        });
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        boolean z = getUserConfig().syncContacts;
        this.newSync = z;
        this.currentSync = z;
        boolean z2 = getUserConfig().suggestContacts;
        this.newSuggest = z2;
        this.currentSuggest = z2;
        updateRows();
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
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
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$DataUsageActivity$3hpqgIR_LlbIO00h4X4rVtsPvXE
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    DataUsageActivity.lambda$onFragmentDestroy$0(tLObject, tL_error);
                }
            });
        }
    }

    static /* synthetic */ void lambda$onFragmentDestroy$0(TLObject response, TLRPC.TL_error error) {
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.mContext = context;
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_listview_layout, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        initActionBar();
        initList();
        return this.fragmentView;
    }

    private void initList() {
        RecyclerListView recyclerListView = (RecyclerListView) this.fragmentView.findViewById(R.attr.listview);
        this.listView = recyclerListView;
        recyclerListView.setLayoutManager(new LinearLayoutManager(this.mContext));
        ListAdapter listAdapter = new ListAdapter();
        this.adapter = listAdapter;
        this.listView.setAdapter(listAdapter);
        this.listView.setOnItemClickListener(new AnonymousClass2());
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.mine.DataUsageActivity$2, reason: invalid class name */
    class AnonymousClass2 implements RecyclerListView.OnItemClickListener {
        AnonymousClass2() {
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
        public void onItemClick(View view, int position) {
            if (position != DataUsageActivity.this.sycnContactsRow) {
                if (position != DataUsageActivity.this.recommendBusyContactRow) {
                    if (position != DataUsageActivity.this.deleteDraftRow) {
                        if (position != DataUsageActivity.this.deletePayInfoRow) {
                            if (position == DataUsageActivity.this.linkReviewRow) {
                                if (DataUsageActivity.this.getMessagesController().secretWebpagePreview == 1) {
                                    DataUsageActivity.this.getMessagesController().secretWebpagePreview = 0;
                                } else {
                                    DataUsageActivity.this.getMessagesController().secretWebpagePreview = 1;
                                }
                                MessagesController.getGlobalMainSettings().edit().putInt("secretWebpage2", DataUsageActivity.this.getMessagesController().secretWebpagePreview).commit();
                                if (view instanceof MryTextCheckCell) {
                                    ((MryTextCheckCell) view).setChecked(DataUsageActivity.this.getMessagesController().secretWebpagePreview == 1);
                                    return;
                                }
                                return;
                            }
                            return;
                        }
                        BottomSheet.Builder builder = new BottomSheet.Builder(DataUsageActivity.this.getParentActivity());
                        builder.setApplyTopPadding(false);
                        builder.setApplyBottomPadding(false);
                        LinearLayout linearLayout = new LinearLayout(DataUsageActivity.this.getParentActivity());
                        linearLayout.setOrientation(1);
                        for (int a = 0; a < 2; a++) {
                            String name = null;
                            if (a == 0) {
                                name = LocaleController.getString("PrivacyClearShipping", R.string.PrivacyClearShipping);
                            } else if (a == 1) {
                                name = LocaleController.getString("PrivacyClearPayment", R.string.PrivacyClearPayment);
                            }
                            DataUsageActivity.this.clear[a] = true;
                            CheckBoxCell checkBoxCell = new CheckBoxCell(DataUsageActivity.this.getParentActivity(), 1, 21);
                            checkBoxCell.setTag(Integer.valueOf(a));
                            checkBoxCell.setBackgroundDrawable(Theme.getSelectorDrawable(false));
                            linearLayout.addView(checkBoxCell, LayoutHelper.createLinear(-1, 50));
                            checkBoxCell.setText(name, null, true, true);
                            checkBoxCell.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
                            checkBoxCell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$DataUsageActivity$2$-g3-NJH2Lz-BU2X8hCLY8BseyXE
                                @Override // android.view.View.OnClickListener
                                public final void onClick(View view2) {
                                    this.f$0.lambda$onItemClick$6$DataUsageActivity$2(view2);
                                }
                            });
                        }
                        BottomSheet.BottomSheetCell cell = new BottomSheet.BottomSheetCell(DataUsageActivity.this.getParentActivity(), 1);
                        cell.setBackgroundDrawable(Theme.getSelectorDrawable(false));
                        cell.setTextAndIcon(LocaleController.getString("ClearButton", R.string.ClearButton).toUpperCase(), 0);
                        cell.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteRedText));
                        cell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$DataUsageActivity$2$ohARGrwTFmav75Gc9Jj44Nk3OTQ
                            @Override // android.view.View.OnClickListener
                            public final void onClick(View view2) {
                                this.f$0.lambda$onItemClick$9$DataUsageActivity$2(view2);
                            }
                        });
                        linearLayout.addView(cell, LayoutHelper.createLinear(-1, 50));
                        builder.setCustomView(linearLayout);
                        DataUsageActivity.this.showDialog(builder.create());
                        return;
                    }
                    XDialog.Builder builder2 = new XDialog.Builder(DataUsageActivity.this.getParentActivity());
                    builder2.setStyle(XDialogStyle.IOS);
                    builder2.setTitle(LocaleController.getString("AppName", R.string.AppName));
                    builder2.setMessage(LocaleController.getString("AreYouSureClearDrafts", R.string.AreYouSureClearDrafts));
                    builder2.setPositiveButton(LocaleController.getString("Delete", R.string.Delete), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$DataUsageActivity$2$ciCgZ-paWqypYZo8nHtgKXWzjuY
                        @Override // android.content.DialogInterface.OnClickListener
                        public final void onClick(DialogInterface dialogInterface, int i) {
                            this.f$0.lambda$onItemClick$5$DataUsageActivity$2(dialogInterface, i);
                        }
                    });
                    builder2.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                    DataUsageActivity.this.showDialog(builder2.create());
                    return;
                }
                final MryTextCheckCell cell2 = (MryTextCheckCell) view;
                if (DataUsageActivity.this.newSuggest) {
                    AlertDialog.Builder builder3 = new AlertDialog.Builder(DataUsageActivity.this.getParentActivity());
                    builder3.setTitle(LocaleController.getString("AppName", R.string.AppName));
                    builder3.setMessage(LocaleController.getString("SuggestContactsAlert", R.string.SuggestContactsAlert));
                    builder3.setPositiveButton(LocaleController.getString("MuteDisable", R.string.MuteDisable), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$DataUsageActivity$2$2gDig93oeizNc6hxfrn4aCHi6Tc
                        @Override // android.content.DialogInterface.OnClickListener
                        public final void onClick(DialogInterface dialogInterface, int i) {
                            this.f$0.lambda$onItemClick$2$DataUsageActivity$2(cell2, dialogInterface, i);
                        }
                    });
                    builder3.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                    DataUsageActivity.this.showDialog(builder3.create());
                    return;
                }
                DataUsageActivity dataUsageActivity = DataUsageActivity.this;
                dataUsageActivity.newSuggest = true ^ dataUsageActivity.newSuggest;
                cell2.setChecked(DataUsageActivity.this.newSuggest);
                return;
            }
            DataUsageActivity dataUsageActivity2 = DataUsageActivity.this;
            dataUsageActivity2.newSync = true ^ dataUsageActivity2.newSync;
            if (view instanceof MryTextCheckCell) {
                ((MryTextCheckCell) view).setChecked(DataUsageActivity.this.newSync);
            }
        }

        public /* synthetic */ void lambda$onItemClick$2$DataUsageActivity$2(final MryTextCheckCell cell, DialogInterface dialogInterface, int i) {
            TLRPC.TL_payments_clearSavedInfo req = new TLRPC.TL_payments_clearSavedInfo();
            req.credentials = DataUsageActivity.this.clear[1];
            req.info = DataUsageActivity.this.clear[0];
            DataUsageActivity.this.getUserConfig().tmpPassword = null;
            DataUsageActivity.this.getUserConfig().saveConfig(false);
            DataUsageActivity.this.getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$DataUsageActivity$2$M8cCu9ILFkSVA3nCXi5nG5xkwP8
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$1$DataUsageActivity$2(cell, tLObject, tL_error);
                }
            });
        }

        public /* synthetic */ void lambda$null$1$DataUsageActivity$2(final MryTextCheckCell cell, TLObject response, TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$DataUsageActivity$2$ySjT7FfbVX0_3jMYfwuOrNEELHg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$0$DataUsageActivity$2(cell);
                }
            });
        }

        public /* synthetic */ void lambda$null$0$DataUsageActivity$2(MryTextCheckCell cell) {
            DataUsageActivity.this.newSuggest = !r0.newSuggest;
            cell.setChecked(DataUsageActivity.this.newSuggest);
        }

        public /* synthetic */ void lambda$onItemClick$5$DataUsageActivity$2(DialogInterface dialogInterface, int i) {
            TLRPC.TL_messages_clearAllDrafts req = new TLRPC.TL_messages_clearAllDrafts();
            DataUsageActivity.this.getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$DataUsageActivity$2$7OgxYnHEJCyy1LvzqtxYEtKNh5c
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$4$DataUsageActivity$2(tLObject, tL_error);
                }
            });
        }

        public /* synthetic */ void lambda$null$3$DataUsageActivity$2() {
            DataUsageActivity.this.getMediaDataController().clearAllDrafts();
        }

        public /* synthetic */ void lambda$null$4$DataUsageActivity$2(TLObject response, TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$DataUsageActivity$2$cMrAZOG6YBP-QQqc-VpZB4y9TtA
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$3$DataUsageActivity$2();
                }
            });
        }

        public /* synthetic */ void lambda$onItemClick$6$DataUsageActivity$2(View v) {
            CheckBoxCell cell = (CheckBoxCell) v;
            int num = ((Integer) cell.getTag()).intValue();
            DataUsageActivity.this.clear[num] = !DataUsageActivity.this.clear[num];
            cell.setChecked(DataUsageActivity.this.clear[num], true);
        }

        public /* synthetic */ void lambda$onItemClick$9$DataUsageActivity$2(View v) {
            try {
                if (DataUsageActivity.this.visibleDialog != null) {
                    DataUsageActivity.this.visibleDialog.dismiss();
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
            AlertDialog.Builder builder1 = new AlertDialog.Builder(DataUsageActivity.this.getParentActivity());
            builder1.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder1.setMessage(LocaleController.getString("PrivacyPaymentsClearAlert", R.string.PrivacyPaymentsClearAlert));
            builder1.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$DataUsageActivity$2$pSTtx8Dl82ghn4YeYhOwCIVOKj8
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$8$DataUsageActivity$2(dialogInterface, i);
                }
            });
            builder1.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            DataUsageActivity.this.showDialog(builder1.create());
        }

        public /* synthetic */ void lambda$null$8$DataUsageActivity$2(DialogInterface dialogInterface, int i) {
            TLRPC.TL_payments_clearSavedInfo req = new TLRPC.TL_payments_clearSavedInfo();
            req.credentials = DataUsageActivity.this.clear[1];
            req.info = DataUsageActivity.this.clear[0];
            DataUsageActivity.this.getUserConfig().tmpPassword = null;
            DataUsageActivity.this.getUserConfig().saveConfig(false);
            DataUsageActivity.this.getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$DataUsageActivity$2$zCSFuUfGin955m2xpve4dspM4sE
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    DataUsageActivity.AnonymousClass2.lambda$null$7(tLObject, tL_error);
                }
            });
        }

        static /* synthetic */ void lambda$null$7(TLObject response, TLRPC.TL_error error) {
        }
    }

    class ListAdapter extends RecyclerListView.SelectionAdapter {
        ListAdapter() {
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int position = holder.getAdapterPosition();
            return position == DataUsageActivity.this.sycnContactsRow || position == DataUsageActivity.this.recommendBusyContactRow || position == DataUsageActivity.this.deleteDraftRow || position == DataUsageActivity.this.deletePayInfoRow || position == DataUsageActivity.this.linkReviewRow;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position != DataUsageActivity.this.contacstSectionRow && position != DataUsageActivity.this.dialogSectionRow && position != DataUsageActivity.this.paySectionRow && position != DataUsageActivity.this.secureSectionRow) {
                if (position != DataUsageActivity.this.deleteDraftRow && position != DataUsageActivity.this.deletePayInfoRow) {
                    if (position != DataUsageActivity.this.sycnContactsRow && position != DataUsageActivity.this.recommendBusyContactRow && position != DataUsageActivity.this.linkReviewRow) {
                        if (position == DataUsageActivity.this.dialogSectionEmptyRow || position == DataUsageActivity.this.emptyRow) {
                            return 4;
                        }
                        return 3;
                    }
                    return 2;
                }
                return 1;
            }
            return 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                view = new HeaderCell(DataUsageActivity.this.mContext);
                RecyclerView.LayoutParams layoutParams = new RecyclerView.LayoutParams(-1, -2);
                layoutParams.leftMargin = AndroidUtilities.dp(10.0f);
                layoutParams.rightMargin = AndroidUtilities.dp(10.0f);
                layoutParams.height = AndroidUtilities.dp(10.0f);
                view.setLayoutParams(layoutParams);
            } else if (viewType == 1) {
                view = new TextSettingCell(DataUsageActivity.this.mContext);
                RecyclerView.LayoutParams layoutParams2 = new RecyclerView.LayoutParams(-1, -2);
                layoutParams2.leftMargin = AndroidUtilities.dp(10.0f);
                layoutParams2.rightMargin = AndroidUtilities.dp(10.0f);
                layoutParams2.height = AndroidUtilities.dp(10.0f);
                view.setLayoutParams(layoutParams2);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == 2) {
                view = new MryTextCheckCell(DataUsageActivity.this.mContext);
                RecyclerView.LayoutParams layoutParams3 = new RecyclerView.LayoutParams(-1, -2);
                layoutParams3.leftMargin = AndroidUtilities.dp(10.0f);
                layoutParams3.rightMargin = AndroidUtilities.dp(10.0f);
                layoutParams3.height = AndroidUtilities.dp(10.0f);
                view.setLayoutParams(layoutParams3);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == 4) {
                view = new ShadowSectionCell(DataUsageActivity.this.mContext);
                RecyclerView.LayoutParams layoutParams4 = new RecyclerView.LayoutParams(-1, -2);
                layoutParams4.leftMargin = AndroidUtilities.dp(10.0f);
                layoutParams4.rightMargin = AndroidUtilities.dp(10.0f);
                layoutParams4.height = AndroidUtilities.dp(10.0f);
                view.setLayoutParams(layoutParams4);
                view.setBackgroundColor(0);
            } else {
                view = new TextInfoPrivacyCell(DataUsageActivity.this.mContext);
                RecyclerView.LayoutParams layoutParams5 = new RecyclerView.LayoutParams(-1, -2);
                layoutParams5.leftMargin = AndroidUtilities.dp(10.0f);
                layoutParams5.rightMargin = AndroidUtilities.dp(10.0f);
                layoutParams5.height = AndroidUtilities.dp(10.0f);
                view.setLayoutParams(layoutParams5);
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            int itemViewType = holder.getItemViewType();
            if (itemViewType == 0) {
                HeaderCell headerCell = (HeaderCell) holder.itemView;
                headerCell.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                if (position != DataUsageActivity.this.contacstSectionRow) {
                    if (position != DataUsageActivity.this.dialogSectionRow) {
                        if (position != DataUsageActivity.this.paySectionRow) {
                            if (position == DataUsageActivity.this.secureSectionRow) {
                                headerCell.setText(LocaleController.getString("DataUsageSecretChat", R.string.DataUsageSecretChat));
                                return;
                            }
                            return;
                        }
                        headerCell.setText(LocaleController.getString("DataUsagePayment", R.string.DataUsagePayment));
                        return;
                    }
                    headerCell.setText(LocaleController.getString("BlockUserChatsTitle", R.string.BlockUserChatsTitle));
                    return;
                }
                headerCell.setText(LocaleController.getString("BlockUserContactsTitle", R.string.BlockUserContactsTitle));
                return;
            }
            if (itemViewType == 1) {
                TextSettingCell textCell = (TextSettingCell) holder.itemView;
                if (position != DataUsageActivity.this.deleteDraftRow) {
                    if (position == DataUsageActivity.this.deletePayInfoRow) {
                        textCell.setText(LocaleController.getString("PrivacyPaymentsClear", R.string.PrivacyPaymentsClear), false);
                        return;
                    }
                    return;
                } else {
                    textCell.setText(LocaleController.getString("PrivacyDeleteCloudDrafts", R.string.PrivacyDeleteCloudDrafts), false);
                    textCell.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                    return;
                }
            }
            if (itemViewType == 2) {
                MryTextCheckCell textCheckCell = (MryTextCheckCell) holder.itemView;
                if (position == DataUsageActivity.this.sycnContactsRow) {
                    textCheckCell.setTextAndCheck(LocaleController.getString("SyncContacts", R.string.SyncContacts), DataUsageActivity.this.newSync, false);
                    textCheckCell.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                    return;
                } else if (position == DataUsageActivity.this.recommendBusyContactRow) {
                    textCheckCell.setTextAndCheck(LocaleController.getString("SuggestContacts", R.string.SuggestContacts), DataUsageActivity.this.newSuggest, false);
                    textCheckCell.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                    return;
                } else {
                    if (position == DataUsageActivity.this.linkReviewRow) {
                        textCheckCell.setTextAndCheck(LocaleController.getString("LinkPreview", R.string.LinkPreview), DataUsageActivity.this.getMessagesController().secretWebpagePreview == 1, false);
                        textCheckCell.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                        return;
                    }
                    return;
                }
            }
            if (itemViewType == 3) {
                TextInfoPrivacyCell privacyCell = (TextInfoPrivacyCell) holder.itemView;
                if (position != DataUsageActivity.this.syncContactsDetailRow) {
                    if (position != DataUsageActivity.this.recommenBusyContactsDetailRow) {
                        if (position != DataUsageActivity.this.deletePayInfoDetailRow) {
                            if (position == DataUsageActivity.this.likReviewDetailRow) {
                                privacyCell.setText(LocaleController.getString("SecretWebPageInfo", R.string.SecretWebPageInfo));
                                return;
                            }
                            return;
                        }
                        privacyCell.setText(LocaleController.getString("PrivacyPaymentsClearInfo", R.string.PrivacyPaymentsClearInfo));
                        return;
                    }
                    privacyCell.setText(LocaleController.getString("SuggestContactsInfo", R.string.SuggestContactsInfo));
                    return;
                }
                privacyCell.setText(LocaleController.getString("SyncContactsInfo", R.string.SyncContactsInfoOff));
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return DataUsageActivity.this.rowCount;
        }
    }
}
