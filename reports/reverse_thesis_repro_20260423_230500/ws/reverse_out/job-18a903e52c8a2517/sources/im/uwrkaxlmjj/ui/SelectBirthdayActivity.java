package im.uwrkaxlmjj.ui;

import android.content.Context;
import android.content.DialogInterface;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.RelativeLayout;
import android.widget.TextView;
import com.bigkoo.pickerview.listener.OnTimeSelectListener;
import com.blankj.utilcode.util.TimeUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.tgnet.TLRPCLogin;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.dialogs.TimeWheelPickerDialog;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import java.util.Calendar;
import java.util.Date;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class SelectBirthdayActivity extends BaseFragment {
    private int item_done = 1;
    private TimeWheelPickerDialog.Builder mTimePickerBuilder;
    private Date selectedDate;
    private MryTextView tvBirthday;
    private TLRPCContacts.CL_userFull_v1 userFull;

    public SelectBirthdayActivity(TLRPCContacts.CL_userFull_v1 userFull) {
        this.userFull = userFull;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_select_birthday, (ViewGroup) null);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        initActionBar();
        initView();
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setCastShadows(false);
        this.actionBar.setTitle(LocaleController.getString(R.string.SelectBirthday));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setActionBarMenuOnItemClick(new AnonymousClass1());
        ActionBarMenu menu = this.actionBar.createMenu();
        menu.addItem(this.item_done, LocaleController.getString(R.string.Done));
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.SelectBirthdayActivity$1, reason: invalid class name */
    class AnonymousClass1 extends ActionBar.ActionBarMenuOnItemClick {
        AnonymousClass1() {
        }

        @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
        public void onItemClick(int id) {
            if (id != -1) {
                if (id != SelectBirthdayActivity.this.item_done || SelectBirthdayActivity.this.userFull == null || SelectBirthdayActivity.this.userFull.getExtendBean() == null) {
                    return;
                }
                Date birthday = new Date(((long) SelectBirthdayActivity.this.userFull.getExtendBean().birthday) * 1000);
                if (!SelectBirthdayActivity.isTheSameDay(birthday, SelectBirthdayActivity.this.selectedDate)) {
                    AlertDialog.Builder builder = new AlertDialog.Builder(SelectBirthdayActivity.this.getParentActivity());
                    builder.setTitle(LocaleController.getString(R.string.AppName));
                    builder.setMessage(LocaleController.getString(R.string.UserBirthOnlyCanModifyOnceContuine));
                    builder.setNegativeButton(LocaleController.getString(R.string.Cancel), null);
                    builder.setPositiveButton(LocaleController.getString(R.string.Confirm), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SelectBirthdayActivity$1$txnSO4l7_cLu1Mosa0s-LM8jh8E
                        @Override // android.content.DialogInterface.OnClickListener
                        public final void onClick(DialogInterface dialogInterface, int i) {
                            this.f$0.lambda$onItemClick$0$SelectBirthdayActivity$1(dialogInterface, i);
                        }
                    });
                    SelectBirthdayActivity.this.showDialog(builder.create());
                    return;
                }
                SelectBirthdayActivity.this.finishFragment();
                return;
            }
            SelectBirthdayActivity.this.finishFragment();
        }

        public /* synthetic */ void lambda$onItemClick$0$SelectBirthdayActivity$1(DialogInterface dialog, int which) {
            SelectBirthdayActivity.this.updateUserExtraInformation();
        }
    }

    private void initView() {
        RelativeLayout rlBirthdayContainer = (RelativeLayout) this.fragmentView.findViewById(R.attr.rl_birthday_container);
        rlBirthdayContainer.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        rlBirthdayContainer.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SelectBirthdayActivity$j_K96henGNecXtRaW1SrRw6ymIw
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initView$0$SelectBirthdayActivity(view);
            }
        });
        this.tvBirthday = (MryTextView) this.fragmentView.findViewById(R.attr.tv_birthday);
        TextView tv_birthday_prefix = (TextView) this.fragmentView.findViewById(R.attr.tv_birthday_prefix);
        tv_birthday_prefix.setText(LocaleController.getString("Birthday", R.string.Birthday));
        TextView tvBirthdayTips = (TextView) this.fragmentView.findViewById(R.attr.tv_birthday_tips);
        tvBirthdayTips.setText(LocaleController.getString("BirthdayTips", R.string.BirthdayTips));
        TLRPCContacts.CL_userFull_v1 cL_userFull_v1 = this.userFull;
        if (cL_userFull_v1 != null && cL_userFull_v1.getExtendBean() != null) {
            Date date = new Date(((long) this.userFull.getExtendBean().birthday) * 1000);
            this.selectedDate = date;
            this.tvBirthday.setText(TimeUtils.millis2String(date.getTime(), LocaleController.getString("yyyy.mm.dd", R.string.formatterYear2)));
        }
    }

    public /* synthetic */ void lambda$initView$0$SelectBirthdayActivity(View v) {
        showSelectBirthDialog();
    }

    private void showSelectBirthDialog() {
        if (this.mTimePickerBuilder == null) {
            this.mTimePickerBuilder = TimeWheelPickerDialog.getDefaultBuilder(getParentActivity(), new OnTimeSelectListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SelectBirthdayActivity$2ZJwOKRn67QdgzjwxaWH14_nvxU
                @Override // com.bigkoo.pickerview.listener.OnTimeSelectListener
                public final void onTimeSelect(Date date, View view) {
                    this.f$0.lambda$showSelectBirthDialog$1$SelectBirthdayActivity(date, view);
                }
            });
        }
        if (this.selectedDate != null) {
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(this.selectedDate);
            this.mTimePickerBuilder.setDate(calendar);
        } else {
            this.mTimePickerBuilder.setDate(Calendar.getInstance());
        }
        showDialog(this.mTimePickerBuilder.build());
    }

    public /* synthetic */ void lambda$showSelectBirthDialog$1$SelectBirthdayActivity(Date date, View v) {
        this.selectedDate = date;
        this.tvBirthday.setText(TimeUtils.millis2String(date.getTime(), LocaleController.getString("yyyy.mm.dd", R.string.formatterYear2)));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateUserExtraInformation() {
        TLRPCLogin.TL_account_updateUserDetail req = new TLRPCLogin.TL_account_updateUserDetail();
        req.birthday = (int) (this.selectedDate.getTime() / 1000);
        if (req.birthday == 0) {
            return;
        }
        getConnectionsManager().bindRequestToGuid(getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SelectBirthdayActivity$PRLSTJHYLHKx7BwDjjd3MkZGVsE
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$updateUserExtraInformation$3$SelectBirthdayActivity(tLObject, tL_error);
            }
        }), this.classGuid);
    }

    public /* synthetic */ void lambda$updateUserExtraInformation$3$SelectBirthdayActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SelectBirthdayActivity$VO3xwq5izVZrOQL1Uu5EjHkW30o
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$2$SelectBirthdayActivity(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$2$SelectBirthdayActivity(TLRPC.TL_error error, TLObject response) {
        TLRPCContacts.CL_userFull_v1 cL_userFull_v1;
        if (error != null) {
            if (error.text != null) {
                if (error.text.contains("ALREDY_CHANGE")) {
                    AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
                    builder.setTitle(LocaleController.getString(R.string.AppName));
                    builder.setMessage(LocaleController.getString(R.string.YouHadModifiedOnceCannotModifyAgain));
                    builder.setPositiveButton(LocaleController.getString(R.string.OK), null);
                    showDialog(builder.create());
                    return;
                }
                if (error.code == 400 || error.text.contains("rpcerror")) {
                    ToastUtils.show(R.string.SetupFail);
                    return;
                } else {
                    ToastUtils.show((CharSequence) LocaleController.getString(R.string.OperationFailedPleaseTryAgain));
                    return;
                }
            }
            return;
        }
        if ((response instanceof TLRPC.UserFull) && this.selectedDate != null && (cL_userFull_v1 = this.userFull) != null && cL_userFull_v1.getExtendBean() != null) {
            this.userFull.getExtendBean().birthday = (int) (this.selectedDate.getTime() / 1000);
        }
    }

    public static boolean isTheSameDay(Date d1, Date d2) {
        Calendar c1 = Calendar.getInstance();
        Calendar c2 = Calendar.getInstance();
        c1.setTime(d1);
        c2.setTime(d2);
        return c1.get(1) == c2.get(1) && c1.get(2) == c2.get(2) && c1.get(5) == c2.get(5);
    }
}
