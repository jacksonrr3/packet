#include "other.h"


	ParseError::ParseError(std::string error)
		: m_error(error){}

	const char* ParseError::what() const noexcept
	{
		return m_error.c_str();
	}


	data::data() {}
	data::data(byte* p, const std::size_t& l) :ptr(p), size(l) {}

	data& data::operator=(const data& d)
	{
		ptr = d.ptr;
		size = d.size;
		return *this;
	}

	Mac::Mac(const data* d, const std::string s)
	{
		_type = s;
		ptr = d->ptr;
		size = d->size;
	}

	std::string Mac::to_string() const 
	{
		std::stringstream ss;
		ss << std::hex << (int)ptr[0] << "." << (int)ptr[1] << "." <<
			(int)ptr[2] << "." << (int)ptr[3] << "." <<
			(int)ptr[4] << "." << (int)ptr[5];
		return std::string(ss.str());
	};

	std::string Mac::type() const 
	{
		return _type;
	}

	Ip::Ip(const data* d, const std::string s)
	{
		_type = s;
		ptr = d->ptr;
		size = d->size;
	}

	std::string Ip::to_string() const 
	{
		return std::to_string(ptr[0]) + "." +
			std::to_string(ptr[1]) + "." +
			std::to_string(ptr[2]) + "." +
			std::to_string(ptr[3]);
	}

	std::string Ip::type() const
	{
		return _type;
	}

	Port::Port(const data* d, const std::string s)
	{
		_type = s;
		ptr = d->ptr;
		size = d->size;
	}

	std::string Port::to_string() const 
	{
		return std::to_string(ptr[0] * 256 + ptr[1]);
	}

	std::string Port::type() const
	{
		return _type;
	}
