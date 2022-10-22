package com.servlet;
import java.util.Vector;
import java.util.*;
import java.util.Random;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import edu.princeton.cs.algs4.StdRandom;



public class GD2CSimulation {
	
	long mTotalSimTime = 0;
	long mTimeUnit = 0;
	//Device[] mSimDevice = null;
	final LinkedList<Device> mDevices = new LinkedList<Device>();
	int mSimType = 0; // 1: Network-absent D2D
					  // 2: Network-covered D2D
					  
	final double mArrivalRate; //\lambda 
	final double mDeviceResidenceTime; //the mean of the residence time to the target device, \lambda_rd
	final double mENBResidenceTime; //the mean of the residence time to the eNB, \lambda_r
	final double mProcessTime;
	final int mNumDevices = 0;
	final StatisticTool mStatisticTool = new StatisticTool(0,0);
	final Lock mLock = new ReentrantLock();
	
	private static class Debug {
		static final boolean mIsDebug = true;
		static void println(String str) {
			if (mIsDebug) System.out.println(str);
		}
		
		static void println(int i) {
			if (mIsDebug) System.out.println(String.valueOf(i));
		}
		
		static void println(double d) {
			if (mIsDebug) System.out.println(String.valueOf(d));
		}
		
		static void println(long l) {
			if (mIsDebug) System.out.println(String.valueOf(l));
		}
	}
	private class StatisticTool {
		int mTotal = 0;
		int mCount = 0;
		StatisticTool (int total, int count) {
			mTotal = total;
			mCount = count;
		}
		
		public void countTotal () {
			mTotal++;
		}
		
		public void count() {
			mCount++;
		}
		
		public int getTotal() {
			return mTotal;
		}
		
		public int getCount() {
			return mCount;
		}
		
		public double rate() {
			return (double)mCount/(double)mTotal;
		}
	}
	
	
	public GD2CSimulation (int type, long sim_time, long time_unit, double arrival_rate, double device_residence_time, double enb_residence_time, double process_time) {
		mSimType = type;
		mTotalSimTime = sim_time;
		mTimeUnit = time_unit;
		mArrivalRate = arrival_rate;					//unit: number 
		mDeviceResidenceTime = device_residence_time;	//
		mENBResidenceTime = enb_residence_time;
		mProcessTime = process_time;
	}
	
	private class Device {
		public long mResidenceTimeD = 0;
		public long mResidenceTimeENB = 0;
		public long mProcessTime = 0;
		public int mNo = 0;
		int mD2DType = 0; 		//1: network-absent D2D communication
								//2: network-covered D2D communication
								
 		 
		//construct a device of network-absent D2D communication
		public Device (long process_time, long res_time_d, int no, int type) {
			this.mProcessTime = process_time;
			this.mResidenceTimeD = res_time_d;
			this.mResidenceTimeENB = -1; //set the residence time in eNB as -1 for network-absent D2D comm.
			this.mNo = no;
			this.mD2DType = type;
		}
		
		//construct a device of network-covered D2D communication
		public Device (long process_time, long res_time_d, long res_time_enb, int no, int type) {
			this.mProcessTime = process_time;
			this.mResidenceTimeD = res_time_d;
			this.mResidenceTimeENB = res_time_enb;
			this.mNo = no;
			this.mD2DType = type;
		}
	}
	
	
	//the timer of simulation
	private class Timer extends Thread {
		//the time unit is millisecond
		long mUnit = 1;
		long mTotalSimTime = 0;
		public Timer (long unit, long sim_time) {
			mUnit = unit;
			mTotalSimTime = sim_time;
		}
		
		public void run () {
			while (mTotalSimTime > 0) {
				mTotalSimTime--;
				try{
					Thread.sleep(1);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
			/*Debug.println(mStatisticTool.getTotal());
			Debug.println(mStatisticTool.getCount());
			Debug.println(mStatisticTool.rate());
			*/
			synchronized (this) {
				notify();
			}	
		}
		
		void resetTimer(long unit, long sim_time) {
			mUnit = unit;
			mTotalSimTime = sim_time;
		}
		
		void setTimeUnit(long unit) {
			if (unit > 0) 
				mUnit = unit;
		}
		void setSimTime (long sim_time) {
			if (sim_time > 0)
				mTotalSimTime = sim_time;
		}
		
		long getUnit() {
			return mUnit;
		}
		
		long getTotalSimTime () {
			return mTotalSimTime;
		}
			
		//count the timer by a unit per call 
		void count (long time) {
			mTotalSimTime -= time;
			if (mTotalSimTime < 0) { mTotalSimTime = 0; }
		}
		
		boolean isZero () {
			if (mTotalSimTime  <= 0) return true;
			else return false;
		}
	}
	
	public void addDevice(Device device) {
		mDevices.offer(device);
	}
	
	public void removeDevice() {
		mDevices.poll();
	}
	
	public Device examineDevice() {
		return mDevices.peek();
	}
	
	
	//simulate the authentication success rate of network-absent D2D communications
	public double simNetworkAbsentD2D () {
		// the thread control the arrivals of devices
		
		final Timer timer = new Timer(mTimeUnit, mTotalSimTime);
		timer.start();
		
		
		Thread arr_thread = new Thread() {
			double arrival_interval = StdRandom.exp(mArrivalRate);
				
			long mArrivalTimeInterval = (long)arrival_interval;
			long mLastTick = 0;
			//private final Object lock = new Object();
			public void run () {
				//Debug.println("ArrivalInterval: "+String.valueOf(arrival_interval));
				mLastTick = timer.getTotalSimTime();
				int no = 1;
				while (!timer.isZero()) {
					//Debug.println("mLastTick:"+String.valueOf(mLastTick));
					long t_interval = mLastTick - timer.getTotalSimTime();
					//Debug.println("t_interval:"+Stxring.valueOf(t_interval));
					if (mArrivalTimeInterval <= t_interval) {
						mArrivalTimeInterval = (long)StdRandom.exp(mArrivalRate);
						//Debug.println("ArrivalTimeInterval:"+String.valueOf(mArrivalTimeInterval));
						if (mSimType == 1) {
							boolean my_lock = mLock.tryLock();
							if (my_lock) {	
								//Debug.println("locked for arrival!!");
								long res_time_d = (long)StdRandom.exp(1/mDeviceResidenceTime);
								//Debug.println("Device"+String.valueOf(no)+" arrived residence time:"+String.valueOf(res_time_d));
								addDevice(new Device((long)mProcessTime, res_time_d, no, mSimType));
								mLock.unlock();
								//Debug.println("unlocked for arrival!!");
							}
							mStatisticTool.countTotal();
							//Debug.println("add a device!!");
							no++;
						} 
						else 
						if (mSimType == 2) {
							long res_time_d = (long)StdRandom.exp(1/mDeviceResidenceTime);
							long res_time_enb = (long)StdRandom.exp(1/mENBResidenceTime);
							boolean my_lock = mLock.tryLock();
							if (my_lock) {
								//Debug.println("locked for arrival!!");
								//("Device"+String.valueOf(no)+" arrived residence time (d):"+String.valueOf(res_time_d)+", residence time (enb):"+String.valueOf(res_time_enb));
								addDevice(new Device((long)mProcessTime,res_time_d, res_time_enb, no, mSimType));
								mLock.unlock();
								//Debug.println("unlocked for arrival!!");
							}
							mStatisticTool.countTotal();
							no++;
						}
						mLastTick = timer.getTotalSimTime();
					}
					yield();
					try {
						Thread.sleep(1);
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
				
			}
		};
		arr_thread.start();
		
		//the thread control the departure of devices from the coverage of the target device
		Thread dep_thread_D = new Thread() {
			private final Object lock = new Object();
			
			public void run () {
				while (!timer.isZero()) {
					boolean my_lock = mLock.tryLock();
					if (my_lock) {
						//Debug.println("locked for departure!!");
						int num_dev = mDevices.size();
						boolean is_depart = false;
						Device d = null;
						for (int i = 0; i < num_dev; i++) {
							try {
								d = mDevices.get(i);
								//Debug.println(String.valueOf(i)+"@@@Device "+String.valueOf(d.mNo)+ " departure time - 1; res time:"+String.valueOf(d.mResidenceTimeD));
							} catch (Exception e) {
								Debug.println("Null point exception!!");
							}
							if (d!=null) {
								//Debug.println("Device"+String.valueOf(d.mNo)+" residence time:"+String.valueOf(d.mResidenceTimeD));
								//if (d.mD2DType == 2) Debug.println("Device"+String.valueOf(d.mNo)+" eNB residence time:"+String.valueOf(d.mResidenceTimeENB));
								d.mResidenceTimeD -= 1;
								if (d.mD2DType == 2) d.mResidenceTimeENB -= 1;
								
								if (d.mResidenceTimeD <= 0){
								
									//Debug.println(mDevices.remove(d));
									is_depart = true;
									//Debug.println("Device"+String.valueOf(d.mNo)+" is departed for mResidenceTimeD = 0. (# of devices="+String.valueOf(mDevices.size())+")");
								}
								else
								if (d.mResidenceTimeENB <= 0 && d.mD2DType == 2) {
								
									//Debug.println(mDevices.remove(d));
									is_depart = true;
									//Debug.println("Device"+String.valueOf(d.mNo)+" is departed for mResidenceTimeENB = 0.(# of devices="+String.valueOf(mDevices.size())+")");
								}
								else {
									mDevices.set(i, d);
								}
							}
						}
						if (is_depart) {
							//Debug.println("*** Device"+String.valueOf(d.mNo)+" is departed. (# of devices="+String.valueOf(mDevices.size())+")");
							mDevices.remove(d);
							is_depart = false;
						}
						mLock.unlock();
						//Debug.println("unlocked for departure!!");
					}
					yield();
					try {
						Thread.sleep(1);
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			}
		};
		dep_thread_D.start();
		
		//the thread control the authentication process
		Thread auth_thread = new Thread() {
			private final Object lock = new Object();
			public void run () {
				while (!timer.isZero()) {
					boolean my_lock = mLock.tryLock();
					if (my_lock) {
						//Debug.println("locked for authentication!!");
						Device d = mDevices.peek();
						if (d != null) {
							d.mProcessTime -= 1;
							//Debug.println("No"+String.valueOf(d.mNo)+"-mProcessTime:" + String.valueOf(d.mProcessTime));
							if (d.mProcessTime <= 0) {
								mDevices.remove(d);
								mStatisticTool.count();
								//Debug.println("Device "+ String.valueOf(d.mNo) +" is Finish authentication!! (# of devices="+String.valueOf(mDevices.size())+")");
							} else {
								mDevices.set(0,d);
							}
						}
						//Debug.println("processing...");
						mLock.unlock();
						//Debug.println("unlocked for authentication!!");
					}
					yield();
					try {
						Thread.sleep(1);
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			}
		};
		auth_thread.start();
		synchronized (timer) {
			try {
				timer.wait();
				//System.out.println("try");
				return mStatisticTool.rate();
			} catch (Exception e) {
				//System.out.println("error");
				e.printStackTrace();
				return 0.0;
			}
		}
	}
	
	
	
	public static void main (String[] args) {
		/*for (int i = 0; i < 100; i++) {
			Debug.println(String.valueOf(StdRandom.exp(0.0005)));
		}*/
		if (args[0].equals("--help")) {
			Debug.println("java GD2CSimulation [type] [simulation time] [time unit] [arrival rate] [residence time of D2D] [residence time in eNB] [process time]");
		}
		else
		if(args.length == 7){
			//GD2CSimulation sim = new GD2CSimulation (1, 10000, 1, 0.01, 150.0, 5000.0, 50.0);
			//GD2CSimulation sim = new GD2CSimulation (Integer.parseInt(args[0]), Long.parseLong(args[1]), Long.parseLong(args[2]), Double.parseDouble(args[3]), Double.parseDouble(args[4]), Double.parseDouble(args[5]), Double.parseDouble(args[6]));
			
			//******simulation for network-absent D2D communication******
			double[] factor = {0.01, 0.0137382, 0.0188739, 0.0259294, 0.0356225, 0.048939, 0.0672336, 0.0923671, 0.126896, 0.174333,
				 0.239503, 0.329034, 0.452035, 0.621017, 0.853168, 1.1721, 1.61026, 2.21222, 3.0392, 4.17532, 5.73615, 7.88046, 10.8264,
					  14.8735, 20.4336, 28.0722, 38.5662, 52.9832, 72.7895, 100};
			int f_len = factor.length;
			double system_auth_time = (Double.parseDouble(args[6]) + 1.0/Double.parseDouble(args[3]));
			System.out.println("System_auth_time:"+String.valueOf(system_auth_time));
			//System.out.println(f_len);
			for (int i = 0; i < f_len; i++) {
				double residence_time_d = system_auth_time*factor[i];
				//System.out.println("still work");
				//System.out.println(residence_time_d);
				//Debug.println("residence time D2D:"+String.valueOf(residence_time_d));
				GD2CSimulation sim = new GD2CSimulation (Integer.parseInt(args[0]), Long.parseLong(args[1]), Long.parseLong(args[2]), Double.parseDouble(args[3]), residence_time_d, Double.parseDouble(args[5]), Double.parseDouble(args[6]));
				//System.out.println("still work");
				double rate = sim.simNetworkAbsentD2D();
				//System.out.println("still work");
				//Debug.println("Authentication success rate:" + String.valueOf(rate));
				Debug.println(String.valueOf(rate));
				//System.out.println(String.valueOf(rate));
				//System.out.println("still work");
			}
			System.out.println("end");
			//******simulation for network-covered D2D communication******
			/*double[] factor = {0.01, 0.0278256, 0.0774264, 0.215443, 0.599484, 1.6681, 4.64159, 12.9155, 35.9381, 100};
			int f_len = factor.length;
			double[][] factor1 = new double[f_len][f_len];
			double[][] factor2 = new double[f_len][f_len];
			
			for (int i = 0; i < f_len; i++) {
				for (int j = 0; j < f_len; j++) {
					factor1[i] = factor;
					factor2[i][j] = factor[i];
				}
			}
			
			for (int i = 0; i < f_len; i++) {
				for (int j = 0; j < f_len; j++) {
					System.out.print (factor1[i][j] + " "); 
				}
				System.out.println (""); 
			}
			
			System.out.println ("");
			for (int i = 0; i < f_len; i++) {
				for (int j = 0; j < f_len; j++) {
					System.out.print (factor2[i][j] + " "); 
				}
				System.out.println (""); 
			}
			
			System.out.println("**********************");
			
			double[] factor3 = {1.0,2.0,3.0,4.0,5.0};
			double system_auth_time = (Double.parseDouble(args[6]) + 1.0/Double.parseDouble(args[3]));
			for (int i = 0; i < factor3.length; i++) {
				for (int j = 0; j < f_len; j++) {
					//double residence_time_d = system_auth_time*factor1[i][j];
					//double residence_time_eNB = residence_time_d*factor2[i][j];
					double residence_time_d = system_auth_time*factor[j];
					double residence_time_eNB = residence_time_d*factor[i];
					//Debug.println("residence time D2D:"+String.valueOf(residence_time_d)+", residence time eNB:"+String.valueOf(residence_time_eNB));
					GD2CSimulation sim = new GD2CSimulation (Integer.parseInt(args[0]), Long.parseLong(args[1]), Long.parseLong(args[2]), Double.parseDouble(args[3]), residence_time_d, residence_time_eNB, Double.parseDouble(args[6]));
					double rate = sim.simNetworkAbsentD2D();
					//Debug.println("Authentication success rate:" + String.valueOf(rate));
					System.out.print(String.valueOf(rate)+ " ");
				}
				System.out.println("");
			}
			*/
			
			/*for (int i = 100; i > 0; i--) {
				double residence_time_d = (1.0/Double.parseDouble(args[3]) + Double.parseDouble(args[6]))/i;
				Debug.println("residence time D2D:"+String.valueOf(residence_time_d));
				GD2CSimulation sim = new GD2CSimulation (Integer.parseInt(args[0]), Long.parseLong(args[1]), Long.parseLong(args[2]), Double.parseDouble(args[3]), residence_time_d, Double.parseDouble(args[5]), Double.parseDouble(args[6]));
				double rate = sim.simNetworkAbsentD2D();
				Debug.println("Authentication success rate:" + String.valueOf(rate));
			}	
			
			for (int i = 2; i < 101; i++) {
				double residence_time_d = (1.0/Double.parseDouble(args[3]) + Double.parseDouble(args[6]))*i;
				Debug.println("residence time D2D:"+String.valueOf(residence_time_d));
				GD2CSimulation sim = new GD2CSimulation (Integer.parseInt(args[0]), Long.parseLong(args[1]), Long.parseLong(args[2]), Double.parseDouble(args[3]), residence_time_d, Double.parseDouble(args[5]), Double.parseDouble(args[6]));
				double rate = sim.simNetworkAbsentD2D();
				Debug.println("Authentication success rate:" + String.valueOf(rate));
			}*/
				//double rate = sim.simNetworkAbsentD2D();
				//Debug.println("Authentication success rate:" + String.valueOf(rate));
		}	
	}
}