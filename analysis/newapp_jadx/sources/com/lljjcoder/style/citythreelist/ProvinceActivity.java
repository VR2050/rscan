package com.lljjcoder.style.citythreelist;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Parcelable;
import android.view.View;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.lljjcoder.style.citylist.bean.CityInfoBean;
import com.lljjcoder.style.citylist.utils.CityListLoader;
import com.lljjcoder.style.citypickerview.C3949R;
import com.lljjcoder.style.citythreelist.CityAdapter;
import com.lljjcoder.widget.RecycleViewDividerForList;
import java.util.List;

/* loaded from: classes2.dex */
public class ProvinceActivity extends Activity {
    public static final int RESULT_DATA = 1001;
    private TextView mCityNameTv;
    private RecyclerView mCityRecyclerView;
    private CityBean provinceBean = new CityBean();

    private void initView() {
        TextView textView = (TextView) findViewById(C3949R.id.cityname_tv);
        this.mCityNameTv = textView;
        textView.setText("选择省份");
        RecyclerView recyclerView = (RecyclerView) findViewById(C3949R.id.city_recyclerview);
        this.mCityRecyclerView = recyclerView;
        recyclerView.setLayoutManager(new LinearLayoutManager(this));
        this.mCityRecyclerView.addItemDecoration(new RecycleViewDividerForList((Context) this, 0, true));
    }

    private void setData() {
        final List<CityInfoBean> proListData = CityListLoader.getInstance().getProListData();
        if (proListData == null) {
            return;
        }
        CityAdapter cityAdapter = new CityAdapter(this, proListData);
        this.mCityRecyclerView.setAdapter(cityAdapter);
        cityAdapter.setOnItemClickListener(new CityAdapter.OnItemSelectedListener() { // from class: com.lljjcoder.style.citythreelist.ProvinceActivity.1
            @Override // com.lljjcoder.style.citythreelist.CityAdapter.OnItemSelectedListener
            public void onItemSelected(View view, int i2) {
                ProvinceActivity.this.provinceBean.setId(((CityInfoBean) proListData.get(i2)).getId());
                ProvinceActivity.this.provinceBean.setName(((CityInfoBean) proListData.get(i2)).getName());
                Intent intent = new Intent(ProvinceActivity.this, (Class<?>) CityActivity.class);
                intent.putExtra(CityListLoader.BUNDATA, (Parcelable) proListData.get(i2));
                ProvinceActivity.this.startActivityForResult(intent, 1001);
            }
        });
    }

    @Override // android.app.Activity
    public void onActivityResult(int i2, int i3, Intent intent) {
        super.onActivityResult(i2, i3, intent);
        if (i2 != 1001 || intent == null) {
            return;
        }
        CityBean cityBean = (CityBean) intent.getParcelableExtra("area");
        CityBean cityBean2 = (CityBean) intent.getParcelableExtra("city");
        Intent intent2 = new Intent();
        intent2.putExtra("province", this.provinceBean);
        intent2.putExtra("city", cityBean2);
        intent2.putExtra("area", cityBean);
        setResult(-1, intent2);
        finish();
    }

    @Override // android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(C3949R.layout.activity_citylist);
        initView();
        setData();
    }
}
