package com.onefun.util;

import java.util.Calendar;
import java.util.Date;
import java.util.Locale;

public class DateUtil {
	/**
     * @Description : date的那月第一天
     * ---------------------------------
     * @Author : Liang.Guangqing
     * @Date : Create in 2017/11/20 10:12
     */
    public static Date getMonthFirstDay(Date date) {
        Calendar calendar = Calendar.getInstance(Locale.CHINA);
        calendar.setTime(date);
        calendar.set(Calendar.DAY_OF_MONTH, calendar.getMinimum(Calendar.DAY_OF_MONTH));
        calendar.set(Calendar.HOUR_OF_DAY, 0);
        //设置当前时刻的分钟为0
        calendar.set(Calendar.MINUTE, 0);
        //设置当前时刻的秒钟为0
        calendar.set(Calendar.SECOND, 0);
        //设置当前的毫秒钟为0
        calendar.set(Calendar.MILLISECOND, 0);
        return calendar.getTime();
    }

    /**
     * @Description : date的那月最后一天
     * ---------------------------------
     * @Author : Liang.Guangqing
     * @Date : Create in 2017/11/20 10:13
     */
    public static Date getMonthLastDay(Date date) {
        Calendar calendar = Calendar.getInstance(Locale.CHINA);
        calendar.setTime(date);
        calendar.set(Calendar.DAY_OF_MONTH, calendar.getActualMaximum(Calendar.DAY_OF_MONTH));
        calendar.set(Calendar.HOUR_OF_DAY, 23);
        //设置当前时刻的分钟为0
        calendar.set(Calendar.MINUTE, 59);
        //设置当前时刻的秒钟为0
        calendar.set(Calendar.SECOND, 59);
        //设置当前的毫秒钟为0
        calendar.set(Calendar.MILLISECOND, 999);
        return calendar.getTime();
    }

    /**
     * 获取当年的第一天
     * @return
     */
    public static Date getCurrYearFirst(){
        Calendar currCal=Calendar.getInstance();
        int currentYear = currCal.get(Calendar.YEAR);
        return getYearFirst(currentYear);
    }

    /**
     * 获取当年的最后一天
     * @return
     */
    public static Date getCurrYearLast(){
        Calendar currCal=Calendar.getInstance();
        int currentYear = currCal.get(Calendar.YEAR);
        return getYearLast(currentYear);
    }

    /**
     * 获取某年第一天日期
     * @param year 年份
     * @return Date
     */
    public static Date getYearFirst(int year){
        Calendar calendar = Calendar.getInstance();
        calendar.clear();
        calendar.set(Calendar.YEAR, year);
        Date currYearFirst = calendar.getTime();
        return currYearFirst;
    }

    /**
     * 获取某年最后一天日期
     * @param year 年份
     * @return Date
     */
    public static Date getYearLast(int year){
        Calendar calendar = Calendar.getInstance();
        calendar.clear();
        calendar.set(Calendar.YEAR, year);
        calendar.roll(Calendar.DAY_OF_YEAR, -1);
        Date currYearLast = calendar.getTime();

        return currYearLast;
    }
}
