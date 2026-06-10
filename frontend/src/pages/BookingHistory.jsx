import { useState, useEffect } from 'react';
import { FaSearch, FaFilter, FaPlane, FaCalendarAlt, FaMapMarkerAlt, FaClock } from 'react-icons/fa';
import { format, parseISO } from 'date-fns';
import { vi } from 'date-fns/locale';
import { getTransactionsByConditions } from '../services/api';
import { toast } from 'react-toastify';
import { useNavigate } from 'react-router-dom';

const BookingCard = ({ booking }) => {
  const navigate = useNavigate();

  const getStatusColor = (status) => {
    switch (status) {
      case 'BOOKED':
        return 'bg-blue-100 text-blue-800';
      case 'CANCEL':
        return 'bg-red-100 text-red-800';
      case 'ONTIME':
        return 'bg-green-100 text-green-800';
      case 'DELAY':
        return 'bg-yellow-100 text-yellow-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const getStatusText = (status) => {
    switch (status) {
      case 'BOOKED':
        return 'Đã đặt';
      case 'CANCEL':
        return 'Đã hủy';
      case 'ONTIME':
        return 'Đã hoàn thành';
      case 'DELAY':
        return 'Bị trễ';
      default:
        return 'Không xác định';
    }
  };

  const formatPrice = (price) => {
    return new Intl.NumberFormat('vi-VN', {
      style: 'currency',
      currency: 'VND'
    }).format(price);
  };

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden hover:shadow-md transition-shadow duration-200">
      <div className="p-6">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-[#F6F6FE] rounded-full flex items-center justify-center">
              <FaPlane className="w-6 h-6 text-[#605DEC]" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-gray-900">
                {booking.flight?.departure} ({booking.flight?.departureCode}) → {booking.flight?.arrival} ({booking.flight?.arrivalCode})
              </h3>
              <p className="text-sm text-gray-500">Mã chuyến bay: {booking.flight?.name}</p>
            </div>
          </div>
          <span className={`px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(booking.status)}`}>
            {getStatusText(booking.status)}
          </span>
        </div>

        <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="flex items-center gap-3">
            <FaCalendarAlt className="w-5 h-5 text-gray-400" />
            <div>
              <p className="text-sm text-gray-500">Ngày khởi hành</p>
              <p className="text-sm font-medium text-gray-900">
                {format(parseISO(booking.flight?.startTime), "dd MMMM yyyy", { locale: vi })}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <FaClock className="w-5 h-5 text-gray-400" />
            <div>
              <p className="text-sm text-gray-500">Thời gian</p>
              <p className="text-sm font-medium text-gray-900">
                {format(parseISO(booking.flight?.startTime), "HH:mm")} - {format(parseISO(booking.flight?.endTime), "HH:mm")}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <FaMapMarkerAlt className="w-5 h-5 text-gray-400" />
            <div>
              <p className="text-sm text-gray-500">Cổng</p>
              <p className="text-sm font-medium text-gray-900">{booking.flight?.gate || 'N/A'}</p>
            </div>
          </div>
        </div>

        <div className="mt-6 pt-6 border-t border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Ghế</p>
              <p className="text-sm font-medium text-gray-900">
                {booking.seat?.name} ({booking.seat?.type})
              </p>
              <p className="text-lg font-semibold text-gray-900 mt-1">{formatPrice(booking.price)}</p>
            </div>
            <button
              onClick={() => navigate(`/booking/${booking.id}`)}
              className="px-4 py-2 bg-[#F6F6FE] text-[#605DEC] rounded-lg hover:bg-[#605DEC] hover:text-white transition-colors duration-200 text-sm font-medium"
            >
              Xem chi tiết
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

const BookingHistory = () => {
  const [bookings, setBookings] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState('BOOKED');
  const [isFilterOpen, setIsFilterOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchBookings = async () => {
      setLoading(true);
      setError(null);
      try {
        // Get current date and adjust date range
        const today = new Date();
        const sixMonthsAgo = new Date();
        const sixMonthsFuture = new Date();
        sixMonthsAgo.setMonth(today.getMonth() - 6);
        sixMonthsFuture.setMonth(today.getMonth() + 6);

        const formattedDateFrom = format(sixMonthsAgo, 'yyyy-MM-dd');
        const formattedDateTo = format(sixMonthsFuture, 'yyyy-MM-dd');

        console.log('Fetching user bookings with params:', {
          flightName: '',
          dateFrom: formattedDateFrom,
          dateTo: formattedDateTo,
          status: filterStatus,
          page: 0,
          size: 100
        });

        try {
          const response = await getTransactionsByConditions(
            '', // flightName
            formattedDateFrom,
            formattedDateTo,
            filterStatus,
            0, // page
            100 // size
          );

          console.log('API Response:', response);

          // Filter only transactions that have a user
          const userBookings = response.data ? response.data.filter(booking => booking.user !== null) : [];
          setBookings(userBookings);

          if (userBookings.length === 0) {
            toast.info("Không tìm thấy vé nào trong khoảng thời gian này");
          }
        } catch (err) {
          // If we get a 400 with "Not found", treat it as empty results
          if (err.response?.status === 400 && err.response?.data === "Not found") {
            setBookings([]);
            toast.info("Không tìm thấy vé nào trong khoảng thời gian này");
            return;
          }
          throw err; // Re-throw other errors to be handled by outer catch
        }
      } catch (err) {
        console.error("Error fetching bookings:", err);
        console.error("Error details:", {
          message: err.message,
          response: err.response?.data,
          status: err.response?.status
        });

        // Handle token expiration
        if (err.response?.status === 401 || err.response?.status === 403) {
          toast.error("Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại.");
          localStorage.removeItem('token');
          navigate('/login');
          return;
        }

        const errorMessage = err.response?.data?.message || "Đã có lỗi xảy ra khi tải lịch sử đặt vé";
        setError(errorMessage);
        toast.error(errorMessage);
      } finally {
        setLoading(false);
      }
    };

    fetchBookings();
  }, [filterStatus, navigate]);

  const filteredBookings = bookings.filter(booking => {
    const matchesSearch = 
      booking.flight?.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      booking.flight?.departure?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      booking.flight?.arrival?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      booking.flight?.departureCode?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      booking.flight?.arrivalCode?.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesSearch;
  });

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-[#605DEC]"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="bg-red-50 p-6 rounded-xl border border-red-200 max-w-md">
          <div className="flex items-center gap-3">
            <svg className="w-6 h-6 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div className="text-red-700 font-medium">{error}</div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="space-y-6">
          {/* Header */}
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <h1 className="text-2xl font-bold text-gray-900">Lịch sử đặt vé</h1>
            
            {/* Search and Filter */}
            <div className="flex items-center gap-4">
              <div className="relative">
                <input
                  type="text"
                  placeholder="Tìm kiếm vé..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full md:w-64 pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-[#605DEC] focus:border-[#605DEC]"
                />
                <FaSearch className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 w-4 h-4" />
              </div>
              
              <div className="relative">
                <button
                  onClick={() => setIsFilterOpen(!isFilterOpen)}
                  className="flex items-center gap-2 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors duration-200"
                >
                  <FaFilter className="w-4 h-4 text-gray-400" />
                  <span className="text-sm text-gray-700">Lọc</span>
                </button>
                
                {isFilterOpen && (
                  <div className="absolute right-0 mt-2 w-48 bg-white rounded-lg shadow-lg border border-gray-200 py-2 z-10">
                    <button
                      onClick={() => {
                        setFilterStatus('BOOKED');
                        setIsFilterOpen(false);
                      }}
                      className={`w-full px-4 py-2 text-left text-sm hover:bg-gray-50 ${
                        filterStatus === 'BOOKED' ? 'text-[#605DEC] font-medium' : 'text-gray-700'
                      }`}
                    >
                      Đã đặt
                    </button>
                    <button
                      onClick={() => {
                        setFilterStatus('ONTIME');
                        setIsFilterOpen(false);
                      }}
                      className={`w-full px-4 py-2 text-left text-sm hover:bg-gray-50 ${
                        filterStatus === 'ONTIME' ? 'text-[#605DEC] font-medium' : 'text-gray-700'
                      }`}
                    >
                      Đã hoàn thành
                    </button>
                    <button
                      onClick={() => {
                        setFilterStatus('CANCEL');
                        setIsFilterOpen(false);
                      }}
                      className={`w-full px-4 py-2 text-left text-sm hover:bg-gray-50 ${
                        filterStatus === 'CANCEL' ? 'text-[#605DEC] font-medium' : 'text-gray-700'
                      }`}
                    >
                      Đã hủy
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Booking List */}
          {filteredBookings.length === 0 ? (
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 text-center">
              <p className="text-gray-500">Không tìm thấy vé nào</p>
            </div>
          ) : (
            <div className="grid gap-6">
              {filteredBookings.map((booking) => (
                <BookingCard key={booking.id} booking={booking} />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default BookingHistory;