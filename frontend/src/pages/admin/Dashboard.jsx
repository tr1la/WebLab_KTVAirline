import { Link } from 'react-router-dom';
import { FaNewspaper, FaPlane, FaCalendarAlt, FaTicketAlt, FaClock } from 'react-icons/fa';

const DashboardCard = ({ title, icon: Icon, to, description }) => {
  return (
    <Link to={to} className="p-6 bg-white rounded-lg shadow-md hover:shadow-lg transition-all">
      <div className="flex items-center justify-between mb-4">
        <div className="text-3xl text-blue-600">
          <Icon />
        </div>
      </div>
      <h3 className="text-xl font-semibold text-gray-800 mb-2">{title}</h3>
      <p className="text-gray-600">{description}</p>
    </Link>
  );
};

const Dashboard = () => {
  const dashboardItems = [
    {
      title: 'Quản lý tin tức & thông báo',
      icon: FaNewspaper,
      to: '/admin/news',
      description: 'Quản lý tin tức, khuyến mãi và thông báo'
    },
    {
      title: 'Quản lý tàu bay',
      icon: FaPlane,
      to: '/admin/planes',
      description: 'Quản lý danh sách và thông tin tàu bay'
    },
    {
      title: 'Quản lý chuyến bay',
      icon: FaCalendarAlt,
      to: '/admin/flights',
      description: 'Quản lý lịch trình và thông tin chuyến bay'
    },
    {
      title: 'Thống kê đặt vé',
      icon: FaTicketAlt,
      to: '/admin/bookings',
      description: 'Xem thống kê và danh sách đặt vé'
    },
  ];

  return (
    <div className="min-h-screen bg-gray-100 p-8">
      <div className="max-w-7xl mx-auto">
        <h1 className="text-3xl font-bold text-gray-800 mb-8">Admin Dashboard</h1>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {dashboardItems.map((item, index) => (
            <DashboardCard key={index} {...item} />
          ))}
        </div>
      </div>
    </div>
  );
};

export default Dashboard; 