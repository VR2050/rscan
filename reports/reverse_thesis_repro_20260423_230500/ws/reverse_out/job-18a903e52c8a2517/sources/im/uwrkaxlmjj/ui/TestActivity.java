package im.uwrkaxlmjj.ui;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import com.google.android.exoplayer2.util.Log;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
@Deprecated
public class TestActivity extends BaseFragment {
    int num = 0;
    int p = 0;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setTitle("Test");
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.TestActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    TestActivity.this.finishFragment();
                }
            }
        });
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_test, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(-16711681);
        this.fragmentView.findViewById(R.attr.siView).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.TestActivity.2
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                Log.e("------->", " xxxxx");
            }
        });
        return this.fragmentView;
    }
}
